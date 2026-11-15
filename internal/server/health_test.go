package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/identities"
	"github.com/ericfitz/agentmesh/internal/core/notify"
	"github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/version"
)

func TestHealthProbeTier(t *testing.T) {
	e := newEnv(t, envOptions{})
	r, err := e.client("").HealthWithResponse(context.Background())
	if err != nil || r.JSON200 == nil {
		t.Fatalf("%v %v", r, err)
	}
	h := r.JSON200
	if h.Tier != "probe" || h.Status != "ok" || h.Version != version.Version || h.Now != fixedNowMs {
		t.Fatalf("%+v", h)
	}
	if h.ProtocolVersion != version.Protocol {
		t.Fatalf("protocol_version %q, want %q", h.ProtocolVersion, version.Protocol)
	}
	if h.StartedAt != nil || h.Store != nil || h.Embeddings != nil || h.Storage != nil || h.Notices != nil || h.Maintenance != nil {
		t.Fatalf("probe tier carries members: %+v", h)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://inproc/v1/health", nil)
	resp := e.raw("", req)
	body, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 5 {
		t.Fatalf("probe body keys = %v, want exactly status, tier, version, protocol_version, now", m)
	}
	for _, k := range []string{"status", "tier", "version", "protocol_version", "now"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("probe body %s lacks %q", body, k)
		}
	}
}

func TestHealthIdentityAndAdminTiers(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("pat", false)
	e.identity("root", true)
	ctx := context.Background()

	r, err := e.client("pat").HealthWithResponse(ctx)
	if err != nil || r.JSON200 == nil {
		t.Fatalf("%v %v", r, err)
	}
	h := r.JSON200
	if h.Tier != "identity" || h.Store == nil || h.Store.Engine != "sqlite" || h.Store.SchemaVersion <= 0 ||
		h.Embeddings == nil || h.Embeddings.State != "off" || h.Embeddings.Model != nil {
		t.Fatalf("identity tier: %+v", h)
	}
	if h.Storage != nil || h.Notices != nil || h.Maintenance != nil {
		t.Fatalf("identity tier carries admin members: %+v", h)
	}

	r, err = e.client("root").HealthWithResponse(ctx)
	if err != nil || r.JSON200 == nil {
		t.Fatalf("%v %v", r, err)
	}
	h = r.JSON200
	if h.Tier != "admin" || h.Storage == nil || h.Storage.Bytes <= 0 || h.Notices == nil || len(*h.Notices) != 0 ||
		h.Maintenance == nil || h.Maintenance.Lock != "unknown" || h.Maintenance.Jobs == nil || len(h.Maintenance.Jobs) != 0 {
		t.Fatalf("admin tier: %+v", h)
	}
}

func TestHealthBadBearerIs401(t *testing.T) {
	e := newEnv(t, envOptions{issuer: true, registration: identities.ModeOpen})
	req, _ := http.NewRequest(http.MethodGet, "http://inproc/v1/health", nil)
	req.Header.Set("Authorization", "Bearer not-a-token")
	resp := e.raw("", req)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/problem+json") {
		t.Fatalf("status %d type %q body %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	var p struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &p); err != nil || p.Code != "unauthenticated" {
		t.Fatalf("code = %q (%v) body %s", p.Code, err, body)
	}
	if strings.Contains(string(body), "not-a-token") {
		t.Fatalf("body carries the token: %s", body)
	}
}

func TestHealthUnregisteredIdentity(t *testing.T) {
	e := newEnv(t, envOptions{})
	r, err := e.client("ghost").HealthWithResponse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode() != 403 || r.JSON200 != nil || len(r.Body) == 0 || problemOf(t, r.Body).Code != "not_registered" {
		t.Fatalf("status %d body %s", r.StatusCode(), r.Body)
	}
}

func TestHealthStoreDownIs503(t *testing.T) {
	e := newEnv(t, envOptions{})
	ctx := context.Background()
	c := e.client("")
	if r, err := c.HealthWithResponse(ctx); err != nil || r.StatusCode() != 200 {
		t.Fatalf("before close: %v %v", r, err)
	}
	if err := e.store.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := c.HealthWithResponse(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode() != 503 {
		t.Fatalf("status %d body %s", r.StatusCode(), r.Body)
	}
	p := problemOf(t, r.Body)
	if p.Code != "unavailable" || !p.Retryable {
		t.Fatalf("status %d problem %+v", r.StatusCode(), p)
	}
	if p.Detail == nil || *p.Detail != "store unreachable" || strings.Contains(*p.Detail, e.dbPath) {
		t.Fatalf("detail = %v", p.Detail)
	}
}

func TestHealthOptionalSecurityIsInTheDocument(t *testing.T) {
	sec := Spec().Paths.Find("/v1/health").Get.Security
	if sec == nil || len(*sec) != 2 {
		t.Fatalf("security = %v, want two requirements", sec)
	}
	if len((*sec)[0]) != 0 {
		t.Fatalf("first requirement = %v, want empty", (*sec)[0])
	}
	if _, ok := (*sec)[1]["bearerAuth"]; !ok || len((*sec)[1]) != 1 {
		t.Fatalf("second requirement = %v, want bearerAuth", (*sec)[1])
	}
}

func TestHealthProbeBodyOmitsNoticeText(t *testing.T) {
	e := newEnv(t, envOptions{})
	err := e.store.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error {
		return tx.SetNotice(ctx, store.Notice{Kind: "capacity", Message: "SECRET-NOTICE-TEXT", SetAt: fixedNowMs})
	})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://inproc/v1/health", nil)
	resp := e.raw("", req)
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "SECRET-NOTICE-TEXT") || !strings.Contains(string(body), `"degraded"`) {
		t.Fatalf("probe body = %s", body)
	}
}

type wireHealthSigning struct {
	Installation string `json:"installation"`
	Intermediate *struct {
		Thumbprint string `json:"thumbprint"`
		DaysLeft   int    `json:"days_left"`
	} `json:"intermediate"`
	Leaf *struct {
		Thumbprint string `json:"thumbprint"`
		NotAfter   int64  `json:"not_after"`
	} `json:"leaf"`
	NextRenewalAt int64   `json:"next_renewal_at"`
	TrustNumber   int64   `json:"trust_number"`
	LastFailureAt int64   `json:"last_failure_at"`
	Stopped       *string `json:"stopped"`
}

func (e *env) healthWire(identity string) (status string, signing *wireHealthSigning) {
	e.t.Helper()
	st, body, _ := e.send(identity, http.MethodGet, "/v1/health")
	if st != 200 {
		e.t.Fatalf("health: %d %s", st, body)
	}
	var h struct {
		Status  string             `json:"status"`
		Signing *wireHealthSigning `json:"signing"`
	}
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		e.t.Fatalf("health body %q: %v", body, err)
	}
	return h.Status, h.Signing
}

// The administrator tier of a server with a leaf manager carries the signing
// section; the identity and probe tiers do not; a stopped manager makes the status
// degraded and the answer is still a 200.
func TestHealthSigningWire(t *testing.T) {
	e := keysEnv(t)
	st, sg := e.healthWire("root")
	if st != "ok" || sg == nil || sg.Installation != e.fx.Installation || sg.Intermediate == nil || sg.Leaf == nil ||
		sg.NextRenewalAt == 0 || sg.TrustNumber != e.mgr.Bundle().TrustNumber || sg.Stopped != nil {
		t.Fatalf("admin tier: %q %+v", st, sg)
	}
	cur, _ := e.mgr.Current()
	if sg.Leaf.Thumbprint != cur {
		t.Errorf("leaf %s, current %s", sg.Leaf.Thumbprint, cur)
	}
	for _, id := range []string{"pat", ""} {
		if _, sg := e.healthWire(id); sg != nil {
			t.Errorf("identity %q sees %+v", id, sg)
		}
	}
	e.clock.Advance(9 * 24 * time.Hour) // the leaf has expired and nothing renewed it
	if st, sg := e.healthWire("root"); st != "degraded" || sg == nil || sg.Leaf == nil || sg.Leaf.NotAfter > e.core.NowMs() {
		t.Errorf("expired leaf: %q %+v", st, sg)
	}
	// local mode: no signing at all.
	l := newEnv(t, envOptions{})
	l.identity("root", true)
	if st, sg := l.healthWire("root"); st != "ok" || sg != nil {
		t.Errorf("local mode: %q %+v", st, sg)
	}
}

// Health answers while a reload is parked inside a Store read holding the
// manager's mutex: the signing section reads the snapshot.
func TestHealthSigningDoesNotWaitForReload(t *testing.T) {
	e := keysEnv(t)
	bs := &blockRead{Store: e.store, entered: make(chan struct{}, 1), release: make(chan struct{})}
	probe, err := core.New(bs, core.Defaults(), core.Options{Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	mgr := e.fx.Manager(t, probe)
	serving, err := core.New(e.store, core.Defaults(), core.Options{Now: e.clock.Now, Notifier: notify.NewMemory(), Trust: mgr})
	if err != nil {
		t.Fatal(err)
	}
	e.core = serving
	bs.armed.Store(true)
	done := make(chan struct{})
	go func() { defer close(done); _ = mgr.Reload(context.Background()) }()
	<-bs.entered
	answered := make(chan *wireHealthSigning, 1)
	go func() { _, sg := e.healthWire("root"); answered <- sg }()
	select {
	case sg := <-answered:
		if sg == nil || sg.Leaf == nil {
			t.Errorf("signing %+v", sg)
		}
	case <-time.After(5 * time.Second):
		t.Error("health waited for the reload")
	}
	close(bs.release)
	<-done
}

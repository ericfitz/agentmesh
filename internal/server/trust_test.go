package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/notify"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/pki/rootca"
	"github.com/ericfitz/agentmesh/internal/store"
)

type wireTrust struct {
	TrustNumber   int64    `json:"trust_number"`
	Intermediates [][]byte `json:"intermediates"`
	RootCRL       []byte   `json:"root_crl"`
	LeafCRLs      [][]byte `json:"leaf_crls"`
	Root          []byte   `json:"root"`
	Installation  *string  `json:"installation"`
}

type wireDiscover struct {
	Trust *wireTrust `json:"trust"`
}

type wireTrustAnswer struct {
	TrustNumber *int64     `json:"trust_number"`
	Trust       *wireTrust `json:"trust"`
	ID          string     `json:"id"`
	Batch       string     `json:"batch"`
}

func (e *env) discover() (int, wireDiscover, string) {
	e.t.Helper()
	st, body, _ := e.send("", http.MethodGet, "/v1/discover")
	var d wireDiscover
	if st == 200 {
		if err := json.Unmarshal([]byte(body), &d); err != nil {
			e.t.Fatalf("discover body %q: %v", body, err)
		}
	}
	return st, d, body
}

// postJSON sends body to path as identity and decodes a 2xx answer into out.
func (e *env) postJSON(identity, path, body string, out any) (int, string) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://inproc"+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp := e.raw(identity, req)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 == 2 && out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s body %q: %v", path, b, err)
		}
	}
	return resp.StatusCode, string(b)
}

func (e *env) openTrust(number string) wireTrustAnswer {
	e.t.Helper()
	body := "{}"
	if number != "" {
		body = fmt.Sprintf(`{"trust_number":%s}`, number)
	}
	var a wireTrustAnswer
	if st, b := e.postJSON("pat", "/v1/sessions", body, &a); st != 201 {
		e.t.Fatalf("open: %d %s", st, b)
	}
	return a
}

func (e *env) receiveTrust(session, number string) wireTrustAnswer {
	e.t.Helper()
	body := "{}"
	if number != "" {
		body = fmt.Sprintf(`{"trust_number":%s}`, number)
	}
	var a wireTrustAnswer
	if st, b := e.postJSON("pat", "/v1/sessions/"+session+"/receive", body, &a); st != 200 {
		e.t.Fatalf("receive: %d %s", st, b)
	}
	return a
}

// addIntermediates stores an expired and a revoked intermediate of this
// installation next to the current one and makes the manager reload, and rotates
// once so a leaf CRL exists. It returns the thumbprints stored.
func addIntermediates(t *testing.T, e *env) []string {
	t.Helper()
	ctx := context.Background()
	tr := e.fx.Trust(e.mgr.Trust().Core)
	expired := e.fx.Renew(t, e.clock.Now().Add(-90*24*time.Hour), 30)
	// A second key under the same name, revoked by the root: the root signs it
	// only with the same-installation flag.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.NewRequest(key, e.fx.Installation)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := rootca.Sign(e.fx.Dir, csr, 30, true, e.clock.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	crlDER, _, err := rootca.Revoke(e.fx.Dir, revoked, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	crl, err := pki.ParseCRL(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []func() error{
		func() error { return putIntermediate(ctx, e, expired) }, // install refuses an expired certificate and a key that is not configured; a row is a fact
		func() error { return putIntermediate(ctx, e, revoked) },
		func() error { _, err := tr.InstallRootCRL(ctx, crl); return err },
	} {
		if err := f(); err != nil {
			t.Fatal(err)
		}
	}
	if st, body := e.rotate("root", ""); st != 200 {
		t.Fatalf("rotate: %d %s", st, body)
	}
	if err := e.mgr.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	return []string{pki.Thumbprint(e.fx.Intermediate.Raw), pki.Thumbprint(expired.Raw), pki.Thumbprint(revoked.Raw)}
}

func putIntermediate(ctx context.Context, e *env, c *x509.Certificate) error {
	return e.store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.PutTrustCertificate(ctx, store.TrustCertificate{
			Kind: store.TrustIntermediate, Thumbprint: pki.Thumbprint(c.Raw), DER: c.Raw,
			NotAfter: c.NotAfter.UnixMilli(), CreatedAt: e.core.NowMs(),
		})
		return err
	})
}

func TestDiscoverCarriesTrust(t *testing.T) {
	e := keysEnv(t)
	want := addIntermediates(t, e)
	st, d, body := e.discover()
	if st != 200 || d.Trust == nil {
		t.Fatalf("discover: %d %s", st, body)
	}
	tr := d.Trust
	if !bytes.Equal(tr.Root, e.fx.Root.Raw) || tr.Installation == nil || *tr.Installation != e.fx.Installation {
		t.Fatalf("root or installation missing: %s", body)
	}
	var got []string
	for _, c := range tr.Intermediates {
		got = append(got, pki.Thumbprint(c))
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("intermediates = %v, want %v (the expired and the revoked among them)", got, want)
	}
	if len(tr.RootCRL) == 0 || len(tr.LeafCRLs) == 0 || tr.TrustNumber <= 0 {
		t.Fatalf("CRLs or number missing: root_crl %d bytes, %d leaf CRLs, number %d", len(tr.RootCRL), len(tr.LeafCRLs), tr.TrustNumber)
	}
	if n := e.mgr.Bundle().TrustNumber; n != tr.TrustNumber {
		t.Fatalf("number %d, the manager holds %d", tr.TrustNumber, n)
	}
}

func TestDiscoverLocalModeHasNoTrust(t *testing.T) {
	e := newEnv(t, envOptions{})
	st, d, body := e.discover()
	if st != 200 || d.Trust != nil || strings.Contains(body, `"trust"`) {
		t.Fatalf("discover in local mode: %d %s", st, body)
	}
}

// The operation's description promises an answer from memory: nothing on its
// path calls the Store.
func TestDiscoverAnswersWithStoreClosed(t *testing.T) {
	e := keysEnv(t)
	if err := e.store.Close(); err != nil {
		t.Fatal(err)
	}
	st, d, body := e.discover()
	if st != 200 || d.Trust == nil || len(d.Trust.Root) == 0 || len(d.Trust.Intermediates) == 0 {
		t.Fatalf("discover with the Store closed: %d %s", st, body)
	}
}

// clientNumbers are the four cases of the table: lower, equal, higher, absent.
func clientNumbers(server int64) []struct {
	name, number string
	attach       bool
} {
	return []struct {
		name, number string
		attach       bool
	}{
		{"lower", fmt.Sprint(server - 1), true},
		{"equal", fmt.Sprint(server), false},
		{"higher", fmt.Sprint(server + 1), true},
		{"absent", "", true},
	}
}

func checkTrustAnswer(t *testing.T, a wireTrustAnswer, server int64, attach bool) {
	t.Helper()
	if a.TrustNumber == nil || *a.TrustNumber != server {
		t.Fatalf("trust_number = %v, want %d", a.TrustNumber, server)
	}
	if (a.Trust != nil) != attach {
		t.Fatalf("trust present = %v, want %v", a.Trust != nil, attach)
	}
	if a.Trust != nil && (len(a.Trust.Root) != 0 || a.Trust.Installation != nil || a.Trust.TrustNumber != server || len(a.Trust.Intermediates) == 0) {
		t.Fatalf("the bundle in a session answer = %+v", a.Trust)
	}
}

func TestOpenSessionTrust(t *testing.T) {
	e := keysEnv(t)
	server := e.mgr.Bundle().TrustNumber
	for _, c := range clientNumbers(server) {
		t.Run(c.name, func(t *testing.T) { checkTrustAnswer(t, e.openTrust(c.number), server, c.attach) })
	}
	t.Run("local mode", func(t *testing.T) {
		l := newEnv(t, envOptions{})
		l.identity("pat", false)
		a := l.openTrust("")
		if a.TrustNumber != nil || a.Trust != nil {
			t.Fatalf("local mode answer carries trust: %+v", a)
		}
	})
}

func TestReceiveTrust(t *testing.T) {
	e := keysEnv(t)
	server := e.mgr.Bundle().TrustNumber
	s := e.openTrust("")
	for _, c := range clientNumbers(server) {
		t.Run(c.name, func(t *testing.T) { checkTrustAnswer(t, e.receiveTrust(s.ID, c.number), server, c.attach) })
	}
	t.Run("local mode", func(t *testing.T) {
		l := newEnv(t, envOptions{})
		l.identity("pat", false)
		a := l.receiveTrust(l.openTrust("").ID, "")
		if a.TrustNumber != nil || a.Trust != nil {
			t.Fatalf("local mode answer carries trust: %+v", a)
		}
	})
}

// A forced renewal on this process: the next open carries the new number at once,
// not after the next periodic reload.
func TestInBandAfterLocalChange(t *testing.T) {
	e := keysEnv(t)
	before := e.openTrust("")
	var rot wireRotation
	if st, body := e.rotate("root", ""); st != 200 {
		t.Fatalf("rotate: %d %s", st, body)
	} else if err := json.Unmarshal([]byte(body), &rot); err != nil {
		t.Fatal(err)
	}
	after := e.openTrust(fmt.Sprint(*before.TrustNumber))
	if *after.TrustNumber != rot.TrustNumber || rot.TrustNumber == *before.TrustNumber || after.Trust == nil || len(after.Trust.LeafCRLs) == 0 {
		t.Fatalf("number before %d, rotation %d, after %d, bundle %+v", *before.TrustNumber, rot.TrustNumber, *after.TrustNumber, after.Trust)
	}
}

// The no-500 rule: a garbage row of each of the four kinds never turns an answer
// into a 500.
func TestTamperedRowsNever500(t *testing.T) {
	e := keysEnv(t)
	ctx := context.Background()
	garbage := []byte("not a DER structure")
	thumb := pki.Thumbprint(garbage)
	err := e.store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		now := e.core.NowMs()
		for _, k := range []string{store.TrustIntermediate, store.TrustLeaf} {
			row := store.TrustCertificate{Kind: k, Thumbprint: thumb, DER: garbage, NotAfter: now + 1000, CreatedAt: now}
			if k == store.TrustLeaf {
				row.IssuerKey = "garbage-issuer"
			}
			if _, err := tx.PutTrustCertificate(ctx, row); err != nil {
				return err
			}
		}
		for _, k := range []string{store.TrustRootCRL, store.TrustLeafCRL} {
			row := store.TrustCRL{Kind: k, Thumbprint: thumb, DER: garbage, Number: 1, CreatedAt: now}
			if k == store.TrustLeafCRL {
				row.IssuerKey = "garbage-issuer"
			}
			if err := tx.PutCRL(ctx, row); err != nil {
				return err
			}
		}
		_, err := tx.BumpTrustNumber(ctx, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// The rows are only seen after a load: reload so the answers below read them.
	if err := e.mgr.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	ok := func(name string, st int, declared ...int) {
		t.Helper()
		if !slices.Contains(declared, st) {
			t.Errorf("%s answered %d, want one of %v", name, st, declared)
		}
	}
	st, d, _ := e.discover()
	ok("discover", st, 200)
	if d.Trust != nil && len(d.Trust.Intermediates) != 1 {
		t.Errorf("discover lists %d intermediates, want only the valid one", len(d.Trust.Intermediates))
	}
	var s wireTrustAnswer
	st, _ = e.postJSON("pat", "/v1/sessions", "{}", &s)
	ok("open", st, 201)
	st, _ = e.postJSON("pat", "/v1/sessions/"+s.ID+"/receive", "{}", nil)
	ok("receive", st, 200)
	req, err := http.NewRequest(http.MethodPost, "http://inproc/v1/auth/token", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := e.rawAllowUnrouted("", req)
	ok("token", resp.StatusCode, 400, 401)
	st, _, _ = e.listKeys("root")
	ok("listSigningKeys", st, 200)
	st, _, _ = e.send("", http.MethodGet, "/v1/auth/jwks")
	ok("jwks", st, 200)
}

// blockRead is a Store whose Read parks until released once armed.
type blockRead struct {
	store.Store
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (b *blockRead) Read(ctx context.Context, fn func(context.Context, store.Tx) error) error {
	if b.armed.Load() {
		select {
		case b.entered <- struct{}{}:
		default:
		}
		select {
		case <-b.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return b.Store.Read(ctx, fn)
}

// A reload parked inside a blocked Store read holds the manager's mutex; discover
// and the in-band answers read the snapshot and never wait for it.
func TestDiscoverDoesNotWaitForReload(t *testing.T) {
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
	h := New(serving, Options{Auth: InProcess{}})

	bs.armed.Store(true)
	done := make(chan struct{})
	go func() { defer close(done); _ = mgr.Reload(context.Background()) }()
	<-bs.entered // the reload is inside the Store read, holding the manager's mutex

	answered := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, "http://inproc/v1/discover", nil)
		resp, err := InProcessTransport(h, "").RoundTrip(req)
		if err != nil {
			answered <- -1
			return
		}
		_ = resp.Body.Close()
		answered <- resp.StatusCode
	}()
	select {
	case st := <-answered:
		if st != 200 {
			t.Errorf("discover = %d", st)
		}
	case <-time.After(5 * time.Second):
		t.Error("discover waited for the reload")
	}
	got := make(chan int64, 1)
	go func() { got <- mgr.Bundle().TrustNumber }()
	select {
	case n := <-got:
		if n <= 0 {
			t.Error("Bundle has no snapshot")
		}
	case <-time.After(5 * time.Second):
		t.Error("Bundle waited for the reload")
	}
	close(bs.release)
	<-done
}

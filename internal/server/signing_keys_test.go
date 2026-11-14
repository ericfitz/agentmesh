package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
)

// countingProvider counts Next calls, so a test can tell that a replayed
// rotation never reached the provider.
type countingProvider struct {
	keyprovider.StoreProvider
	next atomic.Int32
}

func (p *countingProvider) Next(ctx context.Context) (keyprovider.Key, error) {
	p.next.Add(1)
	return p.StoreProvider.Next(ctx)
}

// keysEnv is an env with an issuer, an administrator "root", a non-administrator
// "pat" and a signing key service with one active key (the old key set answers
// in the leaf shape until Task 23).
func keysEnv(t *testing.T) (*env, *countingProvider) {
	t.Helper()
	e := newEnv(t, envOptions{issuer: true, auth: InProcess{}})
	e.identity("root", true)
	e.identity("pat", false)
	p := &countingProvider{}
	svc := signingkeys.Service{Core: e.core, Provider: p, Settings: signingkeys.DefaultSettings()}
	e.opts.SigningKeys = svc
	if _, _, err := svc.EnsureActive(context.Background()); err != nil {
		t.Fatalf("EnsureActive: %v", err)
	}
	p.next.Store(0)
	return e, p
}

type wireKey struct {
	Thumbprint       string `json:"thumbprint"`
	Serial           string `json:"serial"`
	IssuerThumbprint string `json:"issuer_thumbprint"`
	NotBefore        int64  `json:"not_before"`
	NotAfter         int64  `json:"not_after"`
	State            string `json:"state"`
}

type wireRevoked struct {
	Thumbprint    string `json:"thumbprint"`
	HumanMessages int64  `json:"human_messages"`
}

type wireRotation struct {
	Current     wireKey       `json:"current"`
	Revoked     []wireRevoked `json:"revoked"`
	TrustNumber int64         `json:"trust_number"`
}

func (e *env) rotate(identity, idemKey string) (int, string) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://inproc/v1/admin/signing-keys/rotate", nil)
	if err != nil {
		e.t.Fatal(err)
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp := e.raw(identity, req)
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) listKeys(identity string) (int, string, []wireKey) {
	e.t.Helper()
	st, body, _ := e.send(identity, http.MethodGet, "/v1/admin/signing-keys")
	var doc struct {
		Keys []wireKey `json:"keys"`
	}
	if st == 200 {
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			e.t.Fatalf("list body %q: %v", body, err)
		}
	}
	return st, body, doc.Keys
}

func TestListSigningKeysAdmin(t *testing.T) {
	e, _ := keysEnv(t)
	st, body, ks := e.listKeys("root")
	if st != 200 || len(ks) != 1 {
		t.Fatalf("list: %d %s", st, body)
	}
	k := ks[0]
	if k.State != "current" || k.Thumbprint == "" || k.NotBefore != fixedNowMs || k.NotAfter != 0 || k.Serial != "" || k.IssuerThumbprint != "" {
		t.Fatalf("current key = %+v", k)
	}
	if !strings.Contains(body, `"trust_number":0`) {
		t.Fatalf("the list has no trust_number: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "private") || strings.Contains(body, "BEGIN") {
		t.Fatalf("the body names a private key: %s", body)
	}
}

func TestSigningKeysForbiddenForAgent(t *testing.T) {
	e, p := keysEnv(t)
	st, body, _ := e.send("pat", http.MethodGet, "/v1/admin/signing-keys")
	if st != 403 || !strings.Contains(body, `"code":"forbidden"`) {
		t.Fatalf("list as agent: %d %s", st, body)
	}
	st, body = e.rotate("pat", "")
	if st != 403 || !strings.Contains(body, `"code":"forbidden"`) {
		t.Fatalf("rotate as agent: %d %s", st, body)
	}
	if n := p.next.Load(); n != 0 {
		t.Fatalf("a refused rotation called Provider.Next %d times", n)
	}
	if _, _, ks := e.listKeys("root"); len(ks) != 1 {
		t.Fatalf("a refused rotation changed the set: %+v", ks)
	}
}

// Rotate always revokes (Ruling 6): the previous key is deleted, reported as
// the one revoked leaf, and no cooldown refuses a second rotation.
func TestRotateSigningKeyAPI(t *testing.T) {
	e, _ := keysEnv(t)
	_, _, before := e.listKeys("root")
	for i := 0; i < 2; i++ {
		st, body := e.rotate("root", "")
		if st != 200 {
			t.Fatalf("rotate %d: %d %s", i, st, body)
		}
		var r wireRotation
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatal(err)
		}
		if r.Current.State != "current" || r.Current.Thumbprint == before[0].Thumbprint || len(r.Revoked) != 1 ||
			r.Revoked[0].Thumbprint != before[0].Thumbprint || r.Revoked[0].HumanMessages != 0 {
			t.Fatalf("rotation %d = %s", i, body)
		}
		if !strings.Contains(body, `"trust_number":0`) {
			t.Fatalf("the rotation has no trust_number: %s", body)
		}
		_, _, ks := e.listKeys("root")
		if len(ks) != 1 || ks[0].State != "current" || ks[0].Thumbprint != r.Current.Thumbprint {
			t.Fatalf("set after rotate %d = %+v", i, ks)
		}
		before = ks
	}
}

// A set with no key yet answers the first rotation with an empty revoked list.
func TestRotateSigningKeyFirstKey(t *testing.T) {
	e := newEnv(t, envOptions{issuer: true, auth: InProcess{}})
	e.identity("root", true)
	e.opts.SigningKeys = signingkeys.Service{Core: e.core, Provider: keyprovider.StoreProvider{}, Settings: signingkeys.DefaultSettings()}
	st, body := e.rotate("root", "")
	if st != 200 || !strings.Contains(body, `"revoked":[]`) {
		t.Fatalf("first rotate: %d %s", st, body)
	}
}

func TestRotateSigningKeyIdempotent(t *testing.T) {
	e, p := keysEnv(t)
	st, first := e.rotate("root", "k1")
	if st != 200 {
		t.Fatalf("first: %d %s", st, first)
	}
	if n := p.next.Load(); n != 1 {
		t.Fatalf("Next calls after the first = %d", n)
	}
	st, second := e.rotate("root", "k1")
	if st != 200 || second != first {
		t.Fatalf("replay: %d %s\nwant %s", st, second, first)
	}
	if n := p.next.Load(); n != 1 {
		t.Fatalf("a replay called Provider.Next (%d calls)", n)
	}
	var r wireRotation
	if err := json.Unmarshal([]byte(first), &r); err != nil {
		t.Fatal(err)
	}
	if _, _, ks := e.listKeys("root"); len(ks) != 1 || ks[0].Thumbprint != r.Current.Thumbprint {
		t.Fatalf("a replay rotated again: %+v", ks)
	}
}

func TestSigningKeysUnconfigured(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("root", true)
	if e.opts.SigningKeys != nil {
		t.Fatal("the default env sets SigningKeys")
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/signing-keys"},
		{http.MethodPost, "/v1/admin/signing-keys/rotate"},
	} {
		st, body, ct := e.send("root", c.method, c.path)
		if st != 503 || !strings.HasPrefix(ct, "application/problem+json") || !strings.Contains(body, `"code":"unavailable"`) ||
			!strings.Contains(body, `"retryable":false`) || !strings.Contains(body, bus.SigningKeysNotConfigured) {
			t.Errorf("%s %s: %d %s %s", c.method, c.path, st, ct, body)
		}
	}
}

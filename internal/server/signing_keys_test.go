package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
)

// keysEnv is an env with an issuer, an administrator "root", a non-administrator
// "pat" and a leaf manager over a trust fixture made at the fake clock's start
// (a fixture made later would hold certificates that are not valid yet).
func keysEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, envOptions{issuer: true, auth: InProcess{}})
	e.identity("root", true)
	e.identity("pat", false)
	e.opts.SigningKeys = e.mgr
	return e
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
	e := keysEnv(t)
	st, body, ks := e.listKeys("root")
	if st != 200 || len(ks) != 1 {
		t.Fatalf("list: %d %s", st, body)
	}
	k := ks[0]
	if k.State != "current" || k.Thumbprint == "" || k.NotBefore != fixedNowMs-60_000 || k.NotAfter != fixedNowMs+int64(168*time.Hour/time.Millisecond) || k.Serial == "" || k.IssuerThumbprint == "" {
		t.Fatalf("current key = %+v", k)
	}
	var doc struct {
		TrustNumber int64 `json:"trust_number"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil || doc.TrustNumber <= 0 {
		t.Fatalf("the list has no trust_number: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "private") || strings.Contains(body, "BEGIN") {
		t.Fatalf("the body names a private key: %s", body)
	}
}

func TestSigningKeysForbiddenForAgent(t *testing.T) {
	e := keysEnv(t)
	st, body, _ := e.send("pat", http.MethodGet, "/v1/admin/signing-keys")
	if st != 403 || !strings.Contains(body, `"code":"forbidden"`) {
		t.Fatalf("list as agent: %d %s", st, body)
	}
	st, body = e.rotate("pat", "")
	if st != 403 || !strings.Contains(body, `"code":"forbidden"`) {
		t.Fatalf("rotate as agent: %d %s", st, body)
	}
	if _, _, ks := e.listKeys("root"); len(ks) != 1 {
		t.Fatalf("a refused rotation changed the set: %+v", ks)
	}
}

// Rotate always revokes (Ruling 6): the previous leaf is revoked, reported as
// the one revoked leaf, and no cooldown refuses a second rotation.
func TestRotateSigningKeyAPI(t *testing.T) {
	e := keysEnv(t)
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
		if r.TrustNumber <= 0 {
			t.Fatalf("the rotation has no trust_number: %s", body)
		}
		_, _, ks := e.listKeys("root")
		// The revoked leaves stay listed until they expire: one more each time.
		states := map[string]string{}
		for _, k := range ks {
			states[k.Thumbprint] = k.State
		}
		if len(ks) != i+2 || ks[0].State != "current" || ks[0].Thumbprint != r.Current.Thumbprint || states[before[0].Thumbprint] != "revoked" {
			t.Fatalf("set after rotate %d = %+v", i, ks)
		}
		before = ks
	}
}

// A replay of the same Idempotency-Key returns the first answer and issues no
// further leaf.
func TestRotateSigningKeyIdempotent(t *testing.T) {
	e := keysEnv(t)
	st, first := e.rotate("root", "k1")
	if st != 200 {
		t.Fatalf("first: %d %s", st, first)
	}
	_, _, afterFirst := e.listKeys("root")
	st, second := e.rotate("root", "k1")
	if st != 200 || second != first {
		t.Fatalf("replay: %d %s\nwant %s", st, second, first)
	}
	var r wireRotation
	if err := json.Unmarshal([]byte(first), &r); err != nil {
		t.Fatal(err)
	}
	_, _, ks := e.listKeys("root")
	if len(ks) != len(afterFirst) || ks[0].Thumbprint != r.Current.Thumbprint {
		t.Fatalf("a replay rotated again: %+v, was %+v", ks, afterFirst)
	}
}

// The one 409 of rotateSigningKey: an Idempotency-Key the administrator already
// used for another write (the receipt holds another payload). The rotation
// issues no leaf.
func TestRotateSigningKeyKeyUsedElsewhereConflicts(t *testing.T) {
	e := keysEnv(t)
	req, err := http.NewRequest(http.MethodPost, "http://inproc/v1/admin/scopes", strings.NewReader(`{"name":"job1"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "shared")
	if resp := e.raw("root", req); resp.StatusCode != 200 {
		t.Fatalf("create scope: %d", resp.StatusCode)
	}
	_, _, before := e.listKeys("root")
	if st, body := e.rotate("root", "shared"); st != 409 || !strings.Contains(body, `"code":"conflict"`) {
		t.Fatalf("rotate with a key used for another write: %d %s", st, body)
	}
	if _, _, after := e.listKeys("root"); len(after) != len(before) {
		t.Fatalf("the refused rotation issued a leaf: %+v, was %+v", after, before)
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

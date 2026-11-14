package remote

import (
	"context"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
)

const (
	currentKeyJSON  = `{"thumbprint":"T1","serial":"S1","issuer_thumbprint":"I1","not_before":5,"not_after":99,"state":"current"}`
	previousKeyJSON = `{"thumbprint":"T0","serial":"S0","issuer_thumbprint":"I1","not_before":1,"not_after":50,"state":"previous"}`
)

func TestRemoteListSigningKeys(t *testing.T) {
	rec := &recorder{status: 200, ctype: "application/json", body: `{"keys":[` + currentKeyJSON + `,` + previousKeyJSON + `],"trust_number":77}`}
	l, err := New(newRecClient(t, rec)).ListSigningKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.method != "GET" || rec.path != "/v1/admin/signing-keys" {
		t.Fatalf("request %s %s", rec.method, rec.path)
	}
	want := []bus.SigningKey{
		{Thumbprint: "T1", Serial: "S1", IssuerThumbprint: "I1", State: bus.SigningKeyCurrent, NotBefore: 5, NotAfter: 99},
		{Thumbprint: "T0", Serial: "S0", IssuerThumbprint: "I1", State: bus.SigningKeyPrevious, NotBefore: 1, NotAfter: 50},
	}
	if len(l.Keys) != 2 || l.Keys[0] != want[0] || l.Keys[1] != want[1] || l.TrustNumber != 77 {
		t.Fatalf("list = %+v\nwant %+v", l, want)
	}
	// An empty set is an empty slice, not an error.
	rec = &recorder{status: 200, ctype: "application/json", body: `{"keys":[],"trust_number":0}`}
	if l, err = New(newRecClient(t, rec)).ListSigningKeys(context.Background()); err != nil || l.Keys == nil || len(l.Keys) != 0 {
		t.Fatalf("empty = %+v, %v", l, err)
	}
}

func TestRemoteRotateSigningKey(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{status: 200, ctype: "application/json", body: `{"current":` + currentKeyJSON + `,"revoked":[{"thumbprint":"T0","human_messages":0}],"trust_number":78}`}
	b := New(newRecClient(t, rec))
	r, err := b.RotateSigningKey(ctx, bus.RotateSigningKeyInput{IdempotencyKey: "kk"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.method != "POST" || rec.path != "/v1/admin/signing-keys/rotate" || rec.query != "" || rec.header.Get("Idempotency-Key") != "kk" {
		t.Fatalf("request %s %s?%s %v", rec.method, rec.path, rec.query, rec.header)
	}
	if r.Current.Thumbprint != "T1" || len(r.Revoked) != 1 || r.Revoked[0] != (bus.RevokedLeaf{Thumbprint: "T0"}) || r.TrustNumber != 78 {
		t.Fatalf("rotation = %+v", r)
	}

	// Nothing revoked is an empty slice, not nil.
	rec.body = `{"current":` + currentKeyJSON + `,"revoked":[],"trust_number":0}`
	r, err = b.RotateSigningKey(ctx, bus.RotateSigningKeyInput{})
	if err != nil || r.Revoked == nil || len(r.Revoked) != 0 || r.Current.Thumbprint != "T1" {
		t.Fatalf("first rotation = %+v, %v", r, err)
	}
}

func TestRemoteSigningKeysProblem(t *testing.T) {
	rec := &recorder{status: 409, ctype: "application/problem+json",
		body: `{"type":"about:blank","title":"Conflict","status":409,"code":"conflict","detail":"another payload","retryable":false}`}
	b := New(newRecClient(t, rec))
	_, err := b.RotateSigningKey(context.Background(), bus.RotateSigningKeyInput{})
	if bus.CodeOf(err) != bus.CodeConflict || !strings.Contains(err.Error(), "another payload") {
		t.Fatalf("rotate err = %v", err)
	}
	if _, err = b.ListSigningKeys(context.Background()); bus.CodeOf(err) != bus.CodeConflict {
		t.Fatalf("list err = %v", err)
	}
}

// A state outside the closed set, as a server speaking another protocol would
// send it, is an internal error naming the member, on both operations.
func TestRemoteSigningKeysRefuseUnknownEnum(t *testing.T) {
	ctx := context.Background()
	bad := strings.Replace(currentKeyJSON, `"state":"current"`, `"state":"paused"`, 1)
	rec := &recorder{status: 200, ctype: "application/json", body: `{"keys":[` + bad + `],"trust_number":0}`}
	_, err := New(newRecClient(t, rec)).ListSigningKeys(ctx)
	wantInternal(t, err, "state")
	rec = &recorder{status: 200, ctype: "application/json", body: `{"current":` + bad + `,"revoked":[],"trust_number":0}`}
	_, err = New(newRecClient(t, rec)).RotateSigningKey(ctx, bus.RotateSigningKeyInput{})
	wantInternal(t, err, "state")
}

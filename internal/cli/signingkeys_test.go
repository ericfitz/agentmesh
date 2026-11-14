package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/client"
)

// fakeKeysBus answers the signing key operations from canned results and
// records the rotate input; the rest of the Bus is the opened one.
type fakeKeysBus struct {
	bus.Bus
	list bus.SigningKeyList
	res  bus.SigningKeyRotation
	err  error
	got  bus.RotateSigningKeyInput
}

func (f *fakeKeysBus) ListSigningKeys(context.Context) (bus.SigningKeyList, error) {
	return f.list, f.err
}

func (f *fakeKeysBus) RotateSigningKey(_ context.Context, in bus.RotateSigningKeyInput) (bus.SigningKeyRotation, error) {
	f.got = in
	return f.res, f.err
}

func useFakeKeys(t *testing.T) *fakeKeysBus {
	t.Helper()
	fake := &fakeKeysBus{}
	testConn = func(c *client.Conn) { fake.Bus = c.Bus; c.Bus = fake }
	t.Cleanup(func() { testConn = nil })
	return fake
}

func TestSigningKeysList(t *testing.T) {
	e := adminEnv(t)
	fake := useFakeKeys(t)
	run := runner(e, RunSigningKeys)
	fake.list = bus.SigningKeyList{
		Keys: []bus.SigningKey{
			{Thumbprint: "T1", Serial: "S1", IssuerThumbprint: "I1", State: bus.SigningKeyCurrent, NotBefore: 5, NotAfter: 99},
			{Thumbprint: "T0", Serial: "S0", IssuerThumbprint: "I1", State: bus.SigningKeyPrevious, NotBefore: 1, NotAfter: 50},
		},
		TrustNumber: 77,
	}
	code, out, er := run("list")
	if code != 0 {
		t.Fatalf("list: %d %s", code, er)
	}
	var got struct {
		Keys        []map[string]any `json:"keys"`
		TrustNumber float64          `json:"trust_number"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || len(got.Keys) != 2 || got.TrustNumber != 77 {
		t.Fatalf("out %q: %v", out, err)
	}
	want0 := map[string]any{"thumbprint": "T1", "serial": "S1", "issuer_thumbprint": "I1", "not_before": float64(5), "not_after": float64(99), "state": "current"}
	w0, _ := json.Marshal(want0)
	g0, _ := json.Marshal(got.Keys[0])
	if string(w0) != string(g0) {
		t.Fatalf("key 0 = %s\nwant %s", g0, w0)
	}
	if got.Keys[1]["state"] != "previous" || got.Keys[1]["not_after"] != float64(50) {
		t.Fatalf("key 1 = %v", got.Keys[1])
	}
	if strings.Contains(strings.ToLower(out), "private") {
		t.Fatalf("out names a private key: %s", out)
	}

	// An empty set prints keys as [], never null.
	fake.list = bus.SigningKeyList{}
	if code, out, _ = run("list"); code != 0 || !strings.Contains(out, `"keys": []`) {
		t.Fatalf("empty list: %d %q", code, out)
	}
}

func TestSigningKeysRotate(t *testing.T) {
	e := adminEnv(t)
	fake := useFakeKeys(t)
	run := runner(e, RunSigningKeys)
	fake.res = bus.SigningKeyRotation{
		Current:     bus.SigningKey{Thumbprint: "T2", Serial: "S2", IssuerThumbprint: "I1", State: bus.SigningKeyCurrent, NotBefore: 9, NotAfter: 99},
		Revoked:     []bus.RevokedLeaf{{Thumbprint: "T1", HumanMessages: 0}},
		TrustNumber: 78,
	}
	code, out, er := run("rotate", "-key", "K")
	if code != 0 {
		t.Fatalf("rotate: %d %s", code, er)
	}
	if fake.got.IdempotencyKey != "K" {
		t.Fatalf("input = %+v", fake.got)
	}
	var got struct {
		Current     map[string]any   `json:"current"`
		Revoked     []map[string]any `json:"revoked"`
		TrustNumber float64          `json:"trust_number"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.Current["thumbprint"] != "T2" || len(got.Revoked) != 1 ||
		got.Revoked[0]["thumbprint"] != "T1" || got.Revoked[0]["human_messages"] != float64(0) || got.TrustNumber != 78 {
		t.Fatalf("out %q: %v", out, err)
	}

	// Nothing revoked prints revoked as [], never null.
	fake.res = bus.SigningKeyRotation{Current: fake.res.Current}
	code, out, _ = run("rotate")
	if code != 0 || !strings.Contains(out, `"revoked": []`) {
		t.Fatalf("first rotate: %d %s", code, out)
	}
}

func TestSigningKeysBusError(t *testing.T) {
	e := adminEnv(t)
	fake := useFakeKeys(t)
	run := runner(e, RunSigningKeys)
	fake.err = bus.Errorf(bus.CodeConflict, false, "a conflict")
	for _, args := range [][]string{{"list"}, {"rotate"}} {
		code, out, er := run(args...)
		if code != 1 || out != "" || !strings.Contains(er, "agentmesh: conflict: a conflict") {
			t.Fatalf("%v: %d %q %q", args, code, out, er)
		}
	}
}

// On a local profile there are no signing keys; the conformance suite and the
// server answer the same way.
func TestSigningKeysCommandsUnavailableLocally(t *testing.T) {
	e := adminEnv(t)
	run := runner(e, RunSigningKeys)
	for _, args := range [][]string{{"list"}, {"rotate"}} {
		code, _, er := run(args...)
		if code != 1 || !strings.Contains(er, "agentmesh: unavailable: "+bus.SigningKeysNotConfigured) {
			t.Fatalf("%v: %d %q", args, code, er)
		}
	}
}

func TestSigningKeysUsage(t *testing.T) {
	e := adminEnv(t)
	run := runner(e, RunSigningKeys)
	for _, args := range [][]string{{}, {"frob"}, {"list", "extra"}, {"rotate", "-revoke-previous"}, {"rotate", "extra"}, {"rotate", "-from", "x"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Fatalf("%v: exit %d, want 2", args, code)
		}
	}
}

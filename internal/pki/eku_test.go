package pki

import (
	"crypto/x509"
	"testing"
)

func TestExtKeyUsageShape(t *testing.T) {
	id := ExtKeyUsageAgentmesh
	if len(id) != 9 {
		t.Fatalf("%d arcs, want 9", len(id))
	}
	for i, want := range []int{1, 3, 6, 1, 4, 1} {
		if id[i] != want {
			t.Errorf("arc %d = %d, want %d", i, id[i], want)
		}
	}
	if id[7] != 1 || id[8] != 1 {
		t.Errorf("arcs 8 and 9 = %d.%d, want 1.1", id[7], id[8])
	}
	if id[6] != PrivateEnterpriseNumber {
		t.Errorf("arc 7 = %d, want PrivateEnterpriseNumber", id[6])
	}
	for i, a := range id {
		if a >= 1<<31 {
			t.Errorf("arc %d = %d is not below 2^31", i, a)
		}
	}
	f := newFixture(t)
	leaf := f.leaf(t, f.now, MaxLeafLifetime-LeafBackdate)
	if !HasAgentmeshUsage(leaf) {
		t.Error("leaf lacks the agentmesh usage")
	}
	if HasAgentmeshUsage(&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}) {
		t.Error("ExtKeyUsageAny counted as the agentmesh usage")
	}
}

// TestExtKeyUsagePinned pins the identifier to the number IANA assigned to
// Trojan Unicorn Ventures LLC (ADR 0019 Decision 50), written out here so a
// change of the constant alone fails. It refuses 0 and the documentation
// number 32473 (RFC 5612).
func TestExtKeyUsagePinned(t *testing.T) {
	if got, want := ExtKeyUsageAgentmesh.String(), "1.3.6.1.4.1.67669.1.1"; got != want {
		t.Errorf("ExtKeyUsageAgentmesh = %s, want %s", got, want)
	}
	if PrivateEnterpriseNumber == 0 || PrivateEnterpriseNumber == 32473 {
		t.Errorf("PrivateEnterpriseNumber = %d, want the assigned number", PrivateEnterpriseNumber)
	}
}

package signingkeys_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/ericfitz/agentmesh/internal/pki"
)

// Bundle is one snapshot: the number and the material of the load that read it,
// replaced by a reload, answered with the Store closed.
func TestBundleSnapshot(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	m := e.newManager(t)

	b := m.Bundle()
	if b.TrustNumber != e.trustNumber(t) || b.TrustNumber <= 0 {
		t.Fatalf("number = %d, the Store holds %d", b.TrustNumber, e.trustNumber(t))
	}
	if len(b.Intermediates) != 1 || pki.Thumbprint(b.Intermediates[0]) != pki.Thumbprint(e.f.Intermediate.Raw) {
		t.Fatalf("intermediates = %d", len(b.Intermediates))
	}
	if !bytes.Equal(b.Root, e.f.Root.Raw) || b.Installation != e.f.Installation {
		t.Fatal("root or installation is not the pinned one")
	}
	if b.RootCRL != nil || b.Intermediates == nil || b.LeafCRLs == nil || len(b.LeafCRLs) != 0 {
		t.Fatalf("empty parts: root CRL %v, leaf CRLs %v", b.RootCRL, b.LeafCRLs)
	}
}

func TestBundleReplacedByReload(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	m := e.newManager(t)
	before := m.Bundle()

	renewed := e.f.Renew(t, e.clk.now(), 30)
	if _, err := e.tr.InstallIntermediate(context.Background(), renewed); err != nil {
		t.Fatal(err)
	}
	if got := m.Bundle(); got.TrustNumber != before.TrustNumber || len(got.Intermediates) != 1 {
		t.Fatalf("the snapshot changed before a reload: %+v", got)
	}
	if err := m.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := m.Bundle()
	if after.TrustNumber != e.trustNumber(t) || after.TrustNumber == before.TrustNumber || len(after.Intermediates) != 2 {
		t.Fatalf("after a reload: number %d (was %d), %d intermediates", after.TrustNumber, before.TrustNumber, len(after.Intermediates))
	}

	// The snapshot is memory: it answers with the Store closed.
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}
	if got := m.Bundle(); got.TrustNumber != after.TrustNumber {
		t.Fatalf("closed Store: number %d", got.TrustNumber)
	}
}

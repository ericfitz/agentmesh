package signingkeys

import (
	"sort"

	"github.com/ericfitz/agentmesh/internal/bus"
)

var _ interface{ Bundle() bus.TrustBundle } = (*Manager)(nil)

// Bundle is one snapshot of the trust material: the number and the material
// loaded with it (section 4.9), with the root and the installation name for the
// discover document. The snapshot is replaced at every Reload and at once after
// this process's own change, so the number and the bytes never come from two
// loads, and no call reaches the Store or waits for a load (the snapshot is read without
// the manager's mutex). The slices are shared and never
// modified: a caller must not change them.
func (m *Manager) Bundle() bus.TrustBundle {
	if b := m.bundle.Load(); b != nil {
		return *b
	}
	return bus.TrustBundle{}
}

// bundleOf builds the snapshot of mat: every stored intermediate that passes
// the intermediate checks (the revoked and the expired included), the root CRL,
// the leaf CRLs in the order of their issuer keys and the pinned root.
func (t Trust) bundleOf(mat Material) bus.TrustBundle {
	b := bus.TrustBundle{
		TrustNumber:   mat.Number,
		Intermediates: make([][]byte, 0, len(mat.Intermediates)),
		LeafCRLs:      make([][]byte, 0, len(mat.LeafCRLs)),
		Root:          t.Root.Raw,
		Installation:  t.Installation,
	}
	for _, c := range mat.Intermediates {
		b.Intermediates = append(b.Intermediates, c.Raw)
	}
	if mat.RootCRL != nil {
		b.RootCRL = mat.RootCRL.Raw
	}
	issuers := make([]string, 0, len(mat.LeafCRLs))
	for k := range mat.LeafCRLs {
		issuers = append(issuers, k)
	}
	sort.Strings(issuers)
	for _, k := range issuers {
		b.LeafCRLs = append(b.LeafCRLs, mat.LeafCRLs[k].Raw)
	}
	return b
}

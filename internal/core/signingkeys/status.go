package signingkeys

import (
	"crypto/x509"
	"math"
	"sort"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/pki"
)

var _ interface {
	Bundle() bus.TrustBundle
	Signing() bus.HealthSigning
} = (*Manager)(nil)

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

// signingSnap is what Signing reports, copied under mu when the state changes
// (publishLocked) so that no reader waits for a load that holds mu across a
// Store read. Times and days left are worked out at read time.
type signingSnap struct {
	intermediate                *x509.Certificate
	leaf                        *x509.Certificate
	leafNotBefore, leafNotAfter time.Time
	nextRenewal                 time.Time // zero: none scheduled
	trustNumber                 int64
	rootCRL, leafCRL            int64
	failure                     *Failure
	stopped                     string
}

// publishLocked rebuilds the snapshot Signing reads from the state mu guards.
// Caller holds mu. It reads no Store and calls no function that does.
func (m *Manager) publishLocked() {
	sn := &signingSnap{intermediate: m.inUse, stopped: m.stopped}
	if sn.intermediate == nil && m.cur != nil {
		sn.intermediate = m.cur.verified.Intermediate
	}
	if m.loaded {
		sn.trustNumber = m.mat.Number
		if m.mat.RootCRL != nil {
			sn.rootCRL = pki.CRLNumber(m.mat.RootCRL)
		}
		if sn.intermediate != nil {
			if crl := m.mat.LeafCRLs[keyIDOf(sn.intermediate)]; crl != nil {
				sn.leafCRL = pki.CRLNumber(crl)
			}
		}
	}
	if m.cur != nil {
		sn.leaf = m.cur.verified.Leaf
		sn.leafNotBefore, sn.leafNotAfter = m.cur.verified.NotBefore, m.cur.verified.NotAfter
	}
	if m.failure != nil {
		f := *m.failure
		sn.failure = &f
	}
	now := m.trust.Now()
	switch {
	case m.stopped != "" || m.cur == nil:
	case !m.retryAt.IsZero():
		sn.nextRenewal = m.retryAt
	case m.inPeriod(m.cur, now):
		sn.nextRenewal = m.cur.issuedAt.Add(m.validity / 2)
	default:
		sn.nextRenewal = now // outside its period: a new leaf is due at once
	}
	m.signing.Store(sn)
}

// Signing is the state of the signing certificates for the health document
// (section 4.14), worked out at the manager's clock from the snapshot of the last
// change. Like Bundle it never touches the Store and never waits for a load.
func (m *Manager) Signing() bus.HealthSigning {
	out := bus.HealthSigning{Installation: m.trust.Installation}
	sn := m.signing.Load()
	if sn == nil {
		return out
	}
	now := m.trust.Now()
	if sn.intermediate != nil {
		out.Intermediate = healthCertificate(sn.intermediate, sn.intermediate.NotBefore, sn.intermediate.NotAfter, now)
	}
	if sn.leaf != nil {
		out.Leaf = healthCertificate(sn.leaf, sn.leafNotBefore, sn.leafNotAfter, now)
	}
	if !sn.nextRenewal.IsZero() {
		out.NextRenewalAt = sn.nextRenewal.UnixMilli()
	}
	out.TrustNumber, out.RootCRLNumber, out.LeafCRLNumber = sn.trustNumber, sn.rootCRL, sn.leafCRL
	if sn.failure != nil {
		out.LastFailureAt, out.LastFailure = sn.failure.At.UnixMilli(), sn.failure.Message
	}
	out.Stopped = sn.stopped
	return out
}

// healthCertificate is c as the health document shows it; the days left are
// whole days (rounded down, negative once expired).
func healthCertificate(c *x509.Certificate, notBefore, notAfter, now time.Time) *bus.HealthCertificate {
	return &bus.HealthCertificate{
		Thumbprint: pki.Thumbprint(c.Raw),
		NotBefore:  notBefore.UnixMilli(),
		NotAfter:   notAfter.UnixMilli(),
		DaysLeft:   int(math.Floor(notAfter.Sub(now).Hours() / 24)),
	}
}

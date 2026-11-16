package server

import (
	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// Converters for the trust bundle and the signing section of the health
// document (ADR 0019 sections 4.9, 4.11 and 4.14), mirrored by
// internal/bus/remote/convert.go. The members exist on the wire and carry
// nothing until the core fills them (Tasks 28 to 30).

// nonNilBytes is [], never null, for a required array.
func nonNilBytes(b [][]byte) [][]byte {
	if b == nil {
		return [][]byte{}
	}
	return b
}

// optBytes is nil for nil: an optional member is absent, never null.
func optBytes(b []byte) *[]byte {
	if b == nil {
		return nil
	}
	return &b
}

// trustBundleToGen is the wire form of a bundle: the two arrays are [], root
// and root_crl are absent when nil, installation when empty.
func trustBundleToGen(b bus.TrustBundle) gen.TrustBundle {
	return gen.TrustBundle{
		TrustNumber:   b.TrustNumber,
		Intermediates: nonNilBytes(b.Intermediates),
		RootCrl:       optBytes(b.RootCRL),
		LeafCrls:      nonNilBytes(b.LeafCRLs),
		Root:          optBytes(b.Root),
		Installation:  optStr(b.Installation),
	}
}

// trustToGen is nil for a nil bundle: the member is absent.
func trustToGen(b *bus.TrustBundle) *gen.TrustBundle {
	if b == nil {
		return nil
	}
	g := trustBundleToGen(*b)
	return &g
}

func healthCertificateToGen(c bus.HealthCertificate) gen.HealthCertificate {
	return gen.HealthCertificate{Thumbprint: c.Thumbprint, NotBefore: c.NotBefore, NotAfter: c.NotAfter, DaysLeft: c.DaysLeft}
}

func healthCertificateToGenPtr(c *bus.HealthCertificate) *gen.HealthCertificate {
	if c == nil {
		return nil
	}
	g := healthCertificateToGen(*c)
	return &g
}

// healthSigningToGen is the wire form of the signing section: the
// certificates are absent when nil, last_failure and stopped when empty.
func healthSigningToGen(s bus.HealthSigning) gen.HealthSigning {
	return gen.HealthSigning{
		Installation:  s.Installation,
		Intermediate:  healthCertificateToGenPtr(s.Intermediate),
		Leaf:          healthCertificateToGenPtr(s.Leaf),
		NextRenewalAt: s.NextRenewalAt,
		TrustNumber:   s.TrustNumber,
		RootCrlNumber: s.RootCRLNumber,
		LeafCrlNumber: s.LeafCRLNumber,
		LastFailureAt: s.LastFailureAt,
		LastFailure:   optStr(s.LastFailure),
		Stopped:       optStr(s.Stopped),
	}
}

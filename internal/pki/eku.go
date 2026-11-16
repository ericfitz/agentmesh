package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"time"
)

// PrivateEnterpriseNumber is the enterprise number IANA assigned to Trojan
// Unicorn Ventures LLC, under which the agentmesh extended key usage is
// allocated (ADR 0019 Decision 50).
const PrivateEnterpriseNumber = 67669

// ExtKeyUsageAgentmesh is the extended key usage every intermediate and leaf
// carries; a certificate without it is not an agentmesh certificate.
var ExtKeyUsageAgentmesh = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, PrivateEnterpriseNumber, 1, 1}

// MaxLeafLifetime is the longest leaf validity a verifier accepts: 30 days and
// 60 seconds, the second term covering LeafBackdate (Decision 25).
const MaxLeafLifetime = 720*time.Hour + 60*time.Second

// LeafBackdate is how far before issue a leaf's "not before" lies, so a small
// clock difference does not make a fresh leaf look not yet valid (Ruling 13).
const LeafBackdate = 60 * time.Second

// HasAgentmeshUsage reports whether c lists the agentmesh extended key usage.
// ExtKeyUsageAny does not count.
func HasAgentmeshUsage(c *x509.Certificate) bool {
	for _, id := range c.UnknownExtKeyUsage {
		if id.Equal(ExtKeyUsageAgentmesh) {
			return true
		}
	}
	return false
}

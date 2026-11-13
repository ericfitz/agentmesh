package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// The eight refusals of the chain check. Every refusal wraps exactly one.
var (
	ErrChainLength         = errors.New("chain is not a leaf and one intermediate")
	ErrChainSignature      = errors.New("chain signature")
	ErrChainTime           = errors.New("chain validity")
	ErrIntermediateProfile = errors.New("intermediate certificate profile")
	ErrInstallation        = errors.New("installation name")
	ErrExtKeyUsage         = errors.New("extended key usage")
	ErrLeafProfile         = errors.New("leaf certificate profile")
	ErrLeafLifetime        = errors.New("leaf lifetime")
)

// Verified is an accepted chain and the period in which its three
// certificates are all valid.
type Verified struct {
	Leaf, Intermediate  *x509.Certificate
	NotBefore, NotAfter time.Time
}

// ValidAt reports NotBefore-leeway <= at <= NotAfter+leeway.
func (v Verified) ValidAt(at time.Time, leeway time.Duration) bool {
	return !at.Before(v.NotBefore.Add(-leeway)) && !at.After(v.NotAfter.Add(leeway))
}

// VerifyChain is the chain check (spec section 4.2). presented is what the
// verifier was given, leaf first, without the root.
func VerifyChain(presented []*x509.Certificate, root *x509.Certificate, installation string, at time.Time, leeway time.Duration) (Verified, error) {
	v, err := CheckChain(presented, root, installation)
	if err != nil {
		return Verified{}, err
	}
	if !v.ValidAt(at, leeway) {
		return Verified{}, fmt.Errorf("%w: %s is outside %s to %s", ErrChainTime,
			at.UTC().Format(time.RFC3339), v.NotBefore.UTC().Format(time.RFC3339), v.NotAfter.UTC().Format(time.RFC3339))
	}
	return v, nil
}

// CheckChain is VerifyChain without the time: every check but the last.
func CheckChain(presented []*x509.Certificate, root *x509.Certificate, installation string) (Verified, error) {
	if len(presented) != 2 || presented[0] == nil || presented[1] == nil || root == nil {
		return Verified{}, fmt.Errorf("%w: got %d certificates, want a leaf and an intermediate", ErrChainLength, len(presented))
	}
	leaf, inter := presented[0], presented[1]
	if err := CheckIntermediate(inter, root, installation); err != nil {
		return Verified{}, err
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return Verified{}, fmt.Errorf("%w: the leaf is a CA or lacks the digital signature usage", ErrLeafProfile)
	}
	if !HasAgentmeshUsage(leaf) {
		return Verified{}, fmt.Errorf("%w: the leaf lacks the agentmesh extended key usage", ErrExtKeyUsage)
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > MaxLeafLifetime {
		return Verified{}, fmt.Errorf("%w: the leaf is valid for %s, at most %s", ErrLeafLifetime, leaf.NotAfter.Sub(leaf.NotBefore), MaxLeafLifetime)
	}
	nb, na := leaf.NotBefore, leaf.NotAfter
	for _, c := range []*x509.Certificate{inter, root} {
		if c.NotBefore.After(nb) {
			nb = c.NotBefore
		}
		if c.NotAfter.Before(na) {
			na = c.NotAfter
		}
	}
	if nb.After(na) {
		return Verified{}, fmt.Errorf("%w: the leaf, the intermediate and the root are never valid together", ErrChainTime)
	}
	if err := leaf.CheckSignatureFrom(inter); err != nil {
		return Verified{}, fmt.Errorf("%w: the leaf is not signed by the presented intermediate", ErrChainSignature)
	}
	if len(leaf.AuthorityKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, inter.SubjectKeyId) {
		return Verified{}, fmt.Errorf("%w: the leaf's authority key identifier is absent or is not the intermediate's key", ErrLeafProfile)
	}
	roots, pool := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	pool.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		CurrentTime:   nb,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrChainSignature, err)
	}
	return Verified{Leaf: leaf, Intermediate: inter, NotBefore: nb, NotAfter: na}, nil
}

// CheckIntermediate is rule 3 without the time: signed by root, the profile,
// the name, the usage. An expired intermediate passes (it still serves
// history). Each refusal's text is fixed, because "ca install" reports it.
func CheckIntermediate(c, root *x509.Certificate, installation string) error {
	fail := func(sentinel error, format string, args ...any) error {
		return fmt.Errorf("%w: the intermediate certificate "+format, append([]any{sentinel}, args...)...)
	}
	if c == nil {
		return fail(ErrIntermediateProfile, "is missing")
	}
	if root == nil {
		return fail(ErrChainSignature, "cannot be checked without a pinned root")
	}
	if err := c.CheckSignatureFrom(root); err != nil {
		return fail(ErrChainSignature, "does not chain to the pinned root")
	}
	if !c.BasicConstraintsValid || !c.IsCA || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		return fail(ErrIntermediateProfile, "is not a CA with path length 0")
	}
	const both = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if c.KeyUsage&both != both {
		return fail(ErrIntermediateProfile, "lacks the certificate signing or the CRL signing usage")
	}
	if len(c.SubjectKeyId) == 0 {
		return fail(ErrIntermediateProfile, "has no subject key identifier")
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return fail(ErrIntermediateProfile, "its key is not ECDSA P-256")
	}
	if c.Subject.CommonName != installation {
		return fail(ErrInstallation, "names installation %q, expected %q", c.Subject.CommonName, installation)
	}
	if !HasAgentmeshUsage(c) {
		return fail(ErrExtKeyUsage, "lacks the agentmesh extended key usage")
	}
	return nil
}

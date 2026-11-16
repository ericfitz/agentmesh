package pki

import (
	"crypto/x509"
	"math/big"
	"sort"
)

// Revocations is the kept revocations (Decision 27): once a serial number is
// in, it stays.
type Revocations struct {
	Root   []string            `json:"root"`   // revoked intermediate serial numbers (SerialText), sorted
	Leaves map[string][]string `json:"leaves"` // issuer key (KeyID) -> revoked leaf serial numbers, sorted
}

// union returns the sorted, duplicate-free union of a and b.
func union(a, b []string) []string {
	set := make(map[string]bool, len(a)+len(b))
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func crlSerials(crl *x509.RevocationList) []string {
	out := make([]string, 0, len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		out = append(out, SerialText(e.SerialNumber))
	}
	return out
}

// AddRoot keeps the serial numbers of a root CRL.
func (r *Revocations) AddRoot(crl *x509.RevocationList) {
	r.Root = union(r.Root, crlSerials(crl))
}

// AddLeaves keeps the serial numbers of an intermediate's CRL under its key.
func (r *Revocations) AddLeaves(issuerKey string, crl *x509.RevocationList) {
	if r.Leaves == nil {
		r.Leaves = map[string][]string{}
	}
	r.Leaves[issuerKey] = union(r.Leaves[issuerKey], crlSerials(crl))
}

// Merge adds everything in o.
func (r *Revocations) Merge(o Revocations) {
	r.Root = union(r.Root, o.Root)
	for k, v := range o.Leaves {
		if r.Leaves == nil {
			r.Leaves = map[string][]string{}
		}
		r.Leaves[k] = union(r.Leaves[k], v)
	}
}

// RevokedKeys is revocation by key (Decision 26): the KeyID of every
// certificate in intermediates whose serial number is in Root. A listed serial
// number that matches none of them adds nothing.
func (r Revocations) RevokedKeys(intermediates []*x509.Certificate) map[string]bool {
	listed := make(map[string]bool, len(r.Root))
	for _, s := range r.Root {
		listed[s] = true
	}
	out := map[string]bool{}
	for _, c := range intermediates {
		if listed[SerialText(c.SerialNumber)] {
			out[KeyID(c.SubjectKeyId)] = true
		}
	}
	return out
}

// LeafRevoked: the issuer is each listed intermediate that verifies the leaf's
// signature, never the leaf's own authority key identifier (whoever signs a
// leaf chooses that). The leaf is revoked when that intermediate's key is
// revoked or the leaf's serial number is kept for that key. A leaf no listed
// intermediate verifies counts as revoked (fail closed).
func (r Revocations) LeafRevoked(leaf *x509.Certificate, intermediates []*x509.Certificate) bool {
	text := SerialText(leaf.SerialNumber)
	verified := false
	for _, c := range intermediates {
		if leaf.CheckSignatureFrom(c) != nil {
			continue
		}
		verified = true
		issuer := KeyID(c.SubjectKeyId)
		if r.RevokedKeys(intermediates)[issuer] {
			return true
		}
		for _, s := range r.Leaves[issuer] {
			if s == text {
				return true
			}
		}
	}
	return !verified
}

// LeafSerials is the revoked leaf serial numbers kept for an issuer key, in
// order. A text that is not a serial number is skipped.
func (r Revocations) LeafSerials(issuerKey string) []*big.Int {
	var out []*big.Int
	for _, s := range r.Leaves[issuerKey] {
		if n, ok := new(big.Int).SetString(s, 16); ok {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cmp(out[j]) < 0 })
	return out
}

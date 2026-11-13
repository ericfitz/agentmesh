package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerifyChain(t *testing.T) {
	b := fixtureBase
	type tc struct {
		name string
		o    chainOpts
		want error
		pres func(f chainFixture) []*x509.Certificate
		root func(f chainFixture) *x509.Certificate
		at   time.Time
		lee  time.Duration
	}
	otherRoot := func(f chainFixture) *x509.Certificate {
		r, _ := fixtureRoot(t, "another root", b.Add(-time.Hour), b.Add(time.Hour))
		return r
	}
	anotherKey := newP256(t)
	cases := []tc{
		{name: "two-certificates", want: ErrChainLength, pres: func(f chainFixture) []*x509.Certificate { return []*x509.Certificate{f.leaf} }},
		{name: "four-certificates", want: ErrChainLength, pres: func(f chainFixture) []*x509.Certificate {
			return []*x509.Certificate{f.leaf, f.inter, f.root}
		}},
		{name: "wrong-root", want: ErrChainSignature, root: otherRoot},
		{name: "leaf-signed-by-another-key", want: ErrChainSignature, o: chainOpts{leafSigner: anotherKey}},
		{name: "intermediate-path-length-1", want: ErrIntermediateProfile, o: chainOpts{interMod: func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false }}},
		{name: "intermediate-not-ca", want: ErrIntermediateProfile, o: chainOpts{interMod: func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLen = -1; c.MaxPathLenZero = false }}},
		{name: "intermediate-without-crl-sign", want: ErrIntermediateProfile, o: chainOpts{interMod: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign }}},
		{name: "intermediate-without-ski", want: ErrIntermediateProfile, o: chainOpts{interMod: emptySKI}},
		{name: "other-installation", want: ErrInstallation, o: chainOpts{installation: "other"}},
		{name: "intermediate-without-usage", want: ErrExtKeyUsage, o: chainOpts{interMod: func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil }}},
		{name: "leaf-without-usage", want: ErrExtKeyUsage, o: chainOpts{leafMod: func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil }}},
		{name: "leaf-any-usage-only", want: ErrExtKeyUsage, o: chainOpts{leafMod: func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = nil
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}}},
		{name: "leaf-is-ca", want: ErrLeafProfile, o: chainOpts{leafMod: func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }}},
		{name: "leaf-without-digital-signature", want: ErrLeafProfile, o: chainOpts{leafMod: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }}},
		{name: "leaf-lifetime-at-ceiling", o: chainOpts{leafNB: b.Add(-time.Hour), leafNA: b.Add(-time.Hour).Add(MaxLeafLifetime), interNA: b.Add(2000 * time.Hour)}},
		{name: "leaf-lifetime-over", want: ErrLeafLifetime, o: chainOpts{leafNB: b.Add(-time.Hour), leafNA: b.Add(-time.Hour).Add(MaxLeafLifetime + time.Second), interNA: b.Add(2000 * time.Hour)}},
		{name: "intermediate-expired-at-time", want: ErrChainTime, o: chainOpts{interNA: b.Add(-30 * time.Minute)}},
		{name: "root-expired-at-time", want: ErrChainTime, o: chainOpts{rootNA: b.Add(-30 * time.Minute)}},
		{name: "root-not-yet-valid", want: ErrChainTime, o: chainOpts{rootNB: b.Add(time.Hour)}},
		{name: "empty-period", want: ErrChainTime, o: chainOpts{leafNA: b.Add(-30 * time.Minute), interNB: b}},
		{name: "leeway-fails-with-zero", want: ErrChainTime, o: chainOpts{leafNA: b.Add(-30 * time.Second)}},
		{name: "leeway", o: chainOpts{leafNA: b.Add(-30 * time.Second)}, lee: 60 * time.Second},
		{name: "good"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := buildChain(t, c.o)
			pres := f.presented()
			if c.pres != nil {
				pres = c.pres(f)
			}
			root := f.root
			if c.root != nil {
				root = c.root(f)
			}
			at := c.at
			if at.IsZero() {
				at = b
			}
			v, err := VerifyChain(pres, root, "inst", at, c.lee)
			if c.want == nil {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				if c.name == "good" {
					if v.Leaf != f.leaf || v.Intermediate != f.inter {
						t.Fatal("Verified does not hold the presented certificates")
					}
					if !v.NotBefore.Equal(f.leaf.NotBefore) || !v.NotAfter.Equal(f.leaf.NotAfter) {
						t.Fatalf("period %v..%v, want the leaf's %v..%v", v.NotBefore, v.NotAfter, f.leaf.NotBefore, f.leaf.NotAfter)
					}
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

func TestPeriodIsIntersection(t *testing.T) {
	b := fixtureBase
	f := buildChain(t, chainOpts{
		rootNB: b.Add(-3 * time.Hour), rootNA: b.Add(72 * time.Hour),
		interNB: b.Add(-2 * time.Hour), interNA: b.Add(20 * time.Hour),
		leafNB: b.Add(-time.Hour), leafNA: b.Add(24 * time.Hour),
	})
	v, err := CheckChain(f.presented(), f.root, "inst")
	if err != nil {
		t.Fatal(err)
	}
	if !v.NotBefore.Equal(f.leaf.NotBefore) || !v.NotAfter.Equal(f.inter.NotAfter) {
		t.Fatalf("period %v..%v", v.NotBefore, v.NotAfter)
	}
}

func TestValidAtMatchesVerifyChain(t *testing.T) {
	b := fixtureBase
	f := buildChain(t, chainOpts{
		rootNB: b.Add(-3 * time.Hour), rootNA: b.Add(72 * time.Hour),
		interNB: b.Add(-2 * time.Hour), interNA: b.Add(48 * time.Hour),
		leafNB: b.Add(-time.Hour), leafNA: b.Add(24 * time.Hour),
	})
	v, err := CheckChain(f.presented(), f.root, "inst")
	if err != nil {
		t.Fatal(err)
	}
	var times []time.Time
	for _, c := range []*x509.Certificate{f.root, f.inter, f.leaf} {
		times = append(times, c.NotBefore.Add(-time.Second), c.NotBefore.Add(time.Second), c.NotAfter.Add(-time.Second), c.NotAfter.Add(time.Second))
	}
	if len(times) != 12 {
		t.Fatalf("%d times", len(times))
	}
	for _, at := range times {
		_, verr := VerifyChain(f.presented(), f.root, "inst", at, 0)
		if (verr == nil) != v.ValidAt(at, 0) {
			t.Errorf("at %v: VerifyChain error %v, ValidAt %v", at, verr, v.ValidAt(at, 0))
		}
	}
	// A leaf issued in the first minute of a new intermediate.
	g := buildChain(t, chainOpts{interNB: b.Add(-time.Hour), leafNB: b.Add(-time.Hour - time.Minute), leafNA: b.Add(time.Hour)})
	if _, err := CheckChain(g.presented(), g.root, "inst"); err != nil {
		t.Fatalf("leaf starting before its intermediate: %v", err)
	}
}

func TestCheckIntermediateIgnoresTime(t *testing.T) {
	b := fixtureBase
	f := buildChain(t, chainOpts{interNB: b.Add(-48 * time.Hour), interNA: b.Add(-24 * time.Hour), leafNB: b.Add(-47 * time.Hour), leafNA: b.Add(-25 * time.Hour)})
	if err := CheckIntermediate(f.inter, f.root, "inst"); err != nil {
		t.Fatalf("expired intermediate: %v", err)
	}
}

func TestCheckIntermediateMessages(t *testing.T) {
	other, _ := fixtureRoot(t, "another root", fixtureBase.Add(-time.Hour), fixtureBase.Add(time.Hour))
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		o    chainOpts
		root func(chainFixture) *x509.Certificate
		inst string
		want error
		end  string
	}{
		{name: "chain", want: ErrChainSignature, end: "does not chain to the pinned root", root: func(chainFixture) *x509.Certificate { return other }},
		{name: "path-length", want: ErrIntermediateProfile, end: "is not a CA with path length 0", o: chainOpts{interMod: func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false }}},
		{name: "not-ca", want: ErrIntermediateProfile, end: "is not a CA with path length 0", o: chainOpts{interMod: func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLen = -1; c.MaxPathLenZero = false }}},
		{name: "usage", want: ErrIntermediateProfile, end: "lacks the certificate signing or the CRL signing usage", o: chainOpts{interMod: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign }}},
		{name: "ski", want: ErrIntermediateProfile, end: "has no subject key identifier", o: chainOpts{interMod: emptySKI}},
		{name: "key", want: ErrIntermediateProfile, end: "its key is not ECDSA P-256", o: chainOpts{interKey: p384}},
		{name: "name", want: ErrInstallation, end: `names installation "other", expected "inst"`, o: chainOpts{installation: "other"}},
		{name: "eku", want: ErrExtKeyUsage, end: "lacks the agentmesh extended key usage", o: chainOpts{interMod: func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil }}},
		{name: "two-faults-first-reported", want: ErrIntermediateProfile, end: "is not a CA with path length 0", o: chainOpts{installation: "other", interMod: func(c *x509.Certificate) {
			c.MaxPathLen = 1
			c.MaxPathLenZero = false
			c.UnknownExtKeyUsage = nil
		}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := buildChain(t, c.o)
			root := f.root
			if c.root != nil {
				root = c.root(f)
			}
			err := CheckIntermediate(f.inter, root, "inst")
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
			if !strings.HasSuffix(err.Error(), c.end) {
				t.Fatalf("error %q does not end with %q", err, c.end)
			}
		})
	}
}

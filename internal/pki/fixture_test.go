package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// fixtureBase is the time every chain test treats as "now".
var fixtureBase = time.Unix(1_900_000_000, 0).UTC()

// chainFixture is a root, an intermediate and a leaf, each built with the
// fault a test chose.
type chainFixture struct {
	root, inter, leaf *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
}

func (f chainFixture) presented() []*x509.Certificate {
	return []*x509.Certificate{f.leaf, f.inter}
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fixtureCreate(t *testing.T, tmpl, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fixtureSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := serial()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// fixtureRoot makes a root valid in [nb, na].
func fixtureRoot(t *testing.T, cn string, nb, na time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := newP256(t)
	c, err := NewRoot(k, cn, nb, na)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// fixtureInterTemplate is a good intermediate template; a test mutates it.
func fixtureInterTemplate(t *testing.T, cn string, nb, na time.Time) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber:          fixtureSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{ExtKeyUsageAgentmesh},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
}

// fixtureLeafTemplate is a good leaf template; a test mutates it.
func fixtureLeafTemplate(t *testing.T, nb, na time.Time) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber:          fixtureSerial(t),
		Subject:               pkix.Name{CommonName: "agentmesh leaf"},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{ExtKeyUsageAgentmesh},
		BasicConstraintsValid: true,
	}
}

// emptySKI makes Go emit a subject key identifier extension with no bytes (Go
// would otherwise generate one for a CA).
func emptySKI(tmpl *x509.Certificate) {
	tmpl.SubjectKeyId = nil
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{0x04, 0x00},
	})
}

// chainOpts chooses the periods and faults of a fixture. Zero periods mean the
// defaults.
type chainOpts struct {
	installation      string
	rootNB, rootNA    time.Time
	interNB, interNA  time.Time
	leafNB, leafNA    time.Time
	interMod, leafMod func(*x509.Certificate)
	interKey          *ecdsa.PrivateKey       // nil: a new P-256 key
	leafSigner        *ecdsa.PrivateKey       // nil: the intermediate's key
	leafByRoot        bool                    // the root signs the leaf directly
	leafParentMod     func(*x509.Certificate) // changes the intermediate as the leaf's signer sees it (its key identifier, so the leaf's AKI) while its key still signs
}

func orTime(t, def time.Time) time.Time {
	if t.IsZero() {
		return def
	}
	return t
}

func buildChain(t *testing.T, o chainOpts) chainFixture {
	t.Helper()
	if o.installation == "" {
		o.installation = "inst"
	}
	b := fixtureBase
	root, rootKey := fixtureRoot(t, "agentmesh test root", orTime(o.rootNB, b.Add(-10*365*24*time.Hour)), orTime(o.rootNA, b.Add(10*365*24*time.Hour)))
	it := fixtureInterTemplate(t, o.installation, orTime(o.interNB, b.Add(-100*24*time.Hour)), orTime(o.interNA, b.Add(100*24*time.Hour)))
	if o.interMod != nil {
		o.interMod(it)
	}
	interKey := o.interKey
	if interKey == nil {
		interKey = newP256(t)
	}
	inter := fixtureCreate(t, it, root, interKey.Public(), rootKey)
	lt := fixtureLeafTemplate(t, orTime(o.leafNB, b.Add(-time.Hour)), orTime(o.leafNA, b.Add(24*time.Hour)))
	if o.leafMod != nil {
		o.leafMod(lt)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent, signer := inter, interKey
	if o.leafParentMod != nil {
		clone := *inter
		o.leafParentMod(&clone)
		parent = &clone
	}
	if o.leafSigner != nil {
		// Same name and key identifier, another key: the signature cannot verify.
		clone := *inter
		clone.PublicKey = o.leafSigner.Public()
		parent, signer = &clone, o.leafSigner
	}
	if o.leafByRoot {
		parent, signer = root, rootKey
	}
	leaf := fixtureCreate(t, lt, parent, pub, signer)
	return chainFixture{root: root, inter: inter, leaf: leaf, rootKey: rootKey, interKey: interKey}
}

package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/pki"
)

type testCA struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
}

type testInter struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newCA(t testing.TB, name string) testCA {
	t.Helper()
	k := newKey(t)
	now := time.Now()
	r, err := pki.NewRoot(k, name, now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return testCA{r, k}
}

func (c testCA) inter(t testing.TB, name string, notBefore, notAfter time.Time) testInter {
	t.Helper()
	k := newKey(t)
	der, err := pki.NewRequest(k, name)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.IssueIntermediate(c.root, c.rootKey, csr, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	return testInter{cert, k}
}

func (c testCA) validInter(t testing.TB, name string) testInter {
	now := time.Now()
	return c.inter(t, name, now.Add(-time.Minute), now.Add(24*time.Hour))
}

func (c testCA) rootCRL(t testing.TB, number int64, serials ...*big.Int) []byte {
	t.Helper()
	der, err := pki.CreateCRL(c.root, c.rootKey, number, time.Now(), serials)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (i testInter) crl(t testing.TB, number int64, serials ...*big.Int) []byte {
	t.Helper()
	der, err := pki.CreateCRL(i.cert, i.key, number, time.Now(), serials)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (i testInter) keyID() string { return pki.KeyID(i.cert.SubjectKeyId) }

func newStore(t testing.TB) Store {
	t.Helper()
	return Store{Dir: Dir(t.TempDir(), "p")}
}

func discover(c testCA, name string, n int64) Bundle {
	return Bundle{TrustNumber: n, Root: c.root.Raw, Installation: name}
}

func expect(server string) Expect { return Expect{Server: server} }

const srv = "https://mesh.example.test"

// pinned makes a store with a pin for c and name.
func pinned(t testing.TB, c testCA, name string) Store {
	t.Helper()
	s := newStore(t)
	if _, err := s.Accept(discover(c, name, 1), expect(srv), false); err != nil {
		t.Fatal(err)
	}
	return s
}

// snapshot is every file of the directory by name (the lock file excluded).
func snapshot(t testing.TB, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out
		}
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name() == lockFile {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

func names(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func asMismatch(t testing.TB, err error, what string) MismatchError {
	t.Helper()
	var me *MismatchError
	if !errorsAs(err, &me) {
		t.Fatalf("got %v, want a *MismatchError", err)
	}
	if me.What != what {
		t.Fatalf("What = %q, want %q (%v)", me.What, what, err)
	}
	return *me
}

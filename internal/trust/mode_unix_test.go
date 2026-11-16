//go:build !windows

package trust

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestModes(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	in := c.validInter(t, "inst")
	if _, err := s.Apply(Bundle{TrustNumber: 1, Intermediates: [][]byte{in.cert.Raw}, RootCRL: c.rootCRL(t, 1, big.NewInt(1)), LeafCRLs: [][]byte{in.crl(t, 1)}}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(s.Dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v %v", fi.Mode(), err)
	}
	ents, _ := os.ReadDir(s.Dir)
	if len(ents) < 6 {
		t.Fatalf("%d files", len(ents))
	}
	for _, e := range ents {
		fi, err := os.Stat(filepath.Join(s.Dir, e.Name()))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v %v", e.Name(), fi.Mode(), err)
		}
	}
}

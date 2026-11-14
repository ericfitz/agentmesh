package trusttest_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/fileacl"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/store/sqlite"
	"github.com/ericfitz/agentmesh/internal/trusttest"
)

func openCore(t *testing.T) (*core.Core, store.Store) {
	t.Helper()
	st, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "agentmesh.db"), sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	c, err := core.New(st, core.Defaults(), core.Options{Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return c, st
}

func TestFixture(t *testing.T) {
	f := trusttest.New(t, time.Time{})
	if err := pki.CheckIntermediate(f.Intermediate, f.Root, f.Installation); err != nil {
		t.Fatalf("CheckIntermediate: %v", err)
	}
	now := time.Now()
	for _, c := range []struct {
		name        string
		before, aft time.Time
	}{
		{"root", f.Root.NotBefore, f.Root.NotAfter},
		{"intermediate", f.Intermediate.NotBefore, f.Intermediate.NotAfter},
	} {
		if now.Before(c.before) || now.After(c.aft) {
			t.Errorf("%s is not valid at the real time: %v to %v", c.name, c.before, c.aft)
		}
	}
	if f.Installation != "test-installation" {
		t.Errorf("Installation = %q", f.Installation)
	}

	t.Run("key file is owner-only", func(t *testing.T) {
		if err := fileacl.CheckOwnerOnly(f.KeyFile); err != nil {
			t.Errorf("CheckOwnerOnly: %v", err)
		}
		if runtime.GOOS != "windows" {
			fi, err := os.Stat(f.KeyFile)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm()&0o077 != 0 {
				t.Errorf("key file mode %v", fi.Mode().Perm())
			}
		}
	})

	t.Run("Install leaves one intermediate row", func(t *testing.T) {
		c, st := openCore(t)
		f.Install(t, c)
		var rows []store.TrustCertificate
		err := st.Tx(context.Background(), func(ctx context.Context, tx store.Tx) (e error) {
			rows, e = tx.TrustCertificates(ctx, store.TrustIntermediate)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("intermediate rows = %d, want 1", len(rows))
		}
	})

	t.Run("Sibling", func(t *testing.T) {
		s := f.Sibling(t, "other")
		if s.Installation != "other" {
			t.Errorf("Installation = %q", s.Installation)
		}
		if err := pki.CheckIntermediate(s.Intermediate, f.Root, "other"); err != nil {
			t.Errorf("CheckIntermediate: %v", err)
		}
		if s.KeyFile == f.KeyFile || s.CertFile == f.CertFile {
			t.Error("the sibling shares a file with the fixture")
		}
		if bytes.Equal(s.Intermediate.SubjectKeyId, f.Intermediate.SubjectKeyId) {
			t.Error("the sibling has the same key")
		}
		if !bytes.Equal(s.Intermediate.RawIssuer, f.Intermediate.RawIssuer) || s.Root != f.Root || s.RootFile != f.RootFile {
			t.Error("the sibling does not chain to the same root")
		}
		if err := s.Intermediate.CheckSignatureFrom(f.Root); err != nil {
			t.Errorf("signature: %v", err)
		}
	})

	t.Run("Sets", func(t *testing.T) {
		got := f.Sets()
		want := []string{
			"-set", "root_certificate_file=" + f.RootFile,
			"-set", "intermediate_key_file=" + f.KeyFile,
			"-set", "installation_name=" + f.Installation,
		}
		if len(got) != 6 {
			t.Fatalf("Sets has %d elements, want 6: %v", len(got), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("Sets[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})
}

func TestFixtureClock(t *testing.T) {
	at := time.Date(2023, time.November, 14, 12, 0, 0, 0, time.UTC)
	f := trusttest.New(t, at)
	if !f.Now.Equal(at) {
		t.Fatalf("Now = %v, want %v", f.Now, at)
	}
	for _, c := range []struct {
		name string
		nb   time.Time
		na   time.Time
	}{
		{"root", f.Root.NotBefore, f.Root.NotAfter},
		{"intermediate", f.Intermediate.NotBefore, f.Intermediate.NotAfter},
	} {
		valid := func(x time.Time) bool { return !x.Before(c.nb) && !x.After(c.na) }
		if !valid(at) {
			t.Errorf("%s is not valid at the instant", c.name)
		}
		if !valid(at.Add(-time.Hour)) {
			t.Errorf("%s is not valid one hour before", c.name)
		}
		if valid(at.Add(-2 * time.Hour)) {
			t.Errorf("%s is valid two hours before", c.name)
		}
	}

	t.Run("Renew", func(t *testing.T) {
		r := f.Renew(t, at.Add(24*time.Hour), 30)
		if got := r.NotBefore.Sub(at); got != 24*time.Hour {
			t.Errorf("NotBefore is %v after the instant, want 24h", got)
		}
		if !bytes.Equal(r.SubjectKeyId, f.Intermediate.SubjectKeyId) {
			t.Error("the renewal has another subject key identifier")
		}
		if r.SerialNumber.Cmp(f.Intermediate.SerialNumber) == 0 {
			t.Error("the renewal has the same serial number")
		}
	})

	t.Run("RevokeIntermediate", func(t *testing.T) {
		g := trusttest.New(t, at)
		renewed := g.Renew(t, at, 30)
		crl := g.RevokeIntermediate(t, at)
		if err := pki.CheckCRL(crl, g.Root); err != nil {
			t.Fatalf("CheckCRL: %v", err)
		}
		listed := map[string]bool{}
		for _, e := range crl.RevokedCertificateEntries {
			listed[e.SerialNumber.String()] = true
		}
		for _, c := range []string{g.Intermediate.SerialNumber.String(), renewed.SerialNumber.String()} {
			if !listed[c] {
				t.Errorf("serial %s is not on the CRL (%d entries)", c, len(listed))
			}
		}
	})
}

// TestFixtureLeavesNothingOutsideTempDir: every file the fixture names is
// under Dir and Dir is gone once the test that made it ends.
func TestFixtureLeavesNothingOutsideTempDir(t *testing.T) {
	var f *trusttest.Fixture
	t.Run("make", func(t *testing.T) {
		f = trusttest.New(t, time.Time{})
		s := f.Sibling(t, "other")
		f.RevokeIntermediate(t, time.Time{})
		for _, p := range []string{f.RootFile, f.KeyFile, f.CertFile, s.KeyFile, s.CertFile} {
			if rel, err := filepath.Rel(f.Dir, p); err != nil || strings.HasPrefix(rel, "..") {
				t.Errorf("%s is outside %s", p, f.Dir)
			}
		}
		if _, err := os.Stat(f.Dir); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := os.Stat(f.Dir); !os.IsNotExist(err) {
		t.Errorf("%s survives its test (err %v)", f.Dir, err)
	}
}

func TestManager(t *testing.T) {
	f := trusttest.New(t, time.Time{})
	c, st := openCore(t)
	m := f.Manager(t, c) // installs the intermediate: the store has none
	tp, na := m.Current()
	if tp == "" || !na.After(time.Now().Add(167*time.Hour)) || na.After(time.Now().Add(169*time.Hour)) {
		t.Fatalf("Current = %q, %s: want a leaf valid for 168 hours", tp, na)
	}
	var inters, leaves int
	if err := st.Read(context.Background(), func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.TrustCertificates(ctx, store.TrustIntermediate)
		inters = len(rows)
		if err != nil {
			return err
		}
		rows, err = tx.TrustCertificates(ctx, store.TrustLeaf)
		leaves = len(rows)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if inters != 1 || leaves != 1 {
		t.Fatalf("%d intermediates and %d leaves, want 1 and 1", inters, leaves)
	}
	f.Manager(t, c) // a row exists: no second install
	if err := st.Read(context.Background(), func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.TrustCertificates(ctx, store.TrustIntermediate)
		inters = len(rows)
		return err
	}); err != nil || inters != 1 {
		t.Fatalf("%d intermediates after the second Manager (%v)", inters, err)
	}
}

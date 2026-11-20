package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/pki"
)

// `ca init` hands the temporary root.key file to the restrict hook before any
// key byte is written, and a failing hook is exit 1 with no root.key.
func TestCAInitRestrictsKey(t *testing.T) {
	var sizes []int64
	orig := caRestrict
	t.Cleanup(func() { caRestrict = orig })
	caRestrict = func(p string) error {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		sizes = append(sizes, fi.Size())
		return orig(p)
	}
	dir := filepath.Join(t.TempDir(), "root")
	if code, _, errs := runCA(t, "init", "-dir", dir); code != 0 {
		t.Fatalf("init: %d %s", code, errs)
	}
	if len(sizes) != 1 || sizes[0] != 0 {
		t.Errorf("restrict saw sizes %v, want one call at 0 bytes", sizes)
	}

	caRestrict = func(string) error { return os.ErrPermission }
	dir2 := filepath.Join(t.TempDir(), "root")
	code, _, errs := runCA(t, "init", "-dir", dir2)
	if code != 1 || !strings.Contains(errs, "restrict") {
		t.Fatalf("failing restrict: %d %q", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir2, "root.key")); err == nil {
		t.Error("root.key exists after a failed restrict")
	}
}

// A root.key that fails the owner-only check stops sign and revoke (exit 1).
func TestCASignRevokeRefuseExposedKey(t *testing.T) {
	dir := caInit(t)
	tmp := t.TempDir()
	csr := caWrite(t, tmp, "a.csr", pki.EncodePEM("CERTIFICATE REQUEST", caNewCSR(t, "inst-a")))
	code, out, errs := runCA(t, "sign", "-dir", dir, csr)
	if code != 0 {
		t.Fatalf("sign: %d %s", code, errs)
	}
	cert := caWrite(t, tmp, "a.pem", []byte(out))
	orig := caCheck
	t.Cleanup(func() { caCheck = orig })
	caCheck = func(string) error { return errors.New("exposed to others") }
	for _, args := range [][]string{{"sign", "-dir", dir, csr}, {"revoke", "-dir", dir, cert}} {
		code, _, errs := runCA(t, args...)
		if code != 1 || !strings.Contains(errs, "exposed to others") {
			t.Errorf("%s with an exposed key: %d %q", args[0], code, errs)
		}
	}
}

func pkiCSR(t *testing.T) []byte {
	t.Helper()
	return pki.EncodePEM("CERTIFICATE REQUEST", caNewCSR(t, "inst-a"))
}

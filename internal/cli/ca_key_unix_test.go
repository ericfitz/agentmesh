//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckOwnerOnlyKeyMode(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "root.key")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := os.Chmod(key, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkOwnerOnlyKey(key); err != nil {
			t.Errorf("mode %o refused: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(key, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkOwnerOnlyKey(key); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
	if err := checkOwnerOnlyKey(filepath.Join(dir, "absent")); err == nil {
		t.Error("a missing file passed")
	}
	if err := checkOwnerOnlyKey(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: %v", err)
	}
	// A symlink is followed: the target's mode counts.
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if err := checkOwnerOnlyKey(link); err == nil {
		t.Error("a symlink to a 0644 file passed")
	}
}

// End to end on Unix: a root.key opened up to other accounts stops `ca sign`.
func TestCASignRefusesWorldReadableKey(t *testing.T) {
	dir := caInit(t)
	if err := os.Chmod(filepath.Join(dir, "root.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	csr := caWrite(t, t.TempDir(), "a.csr", pkiCSR(t))
	code, _, errs := runCA(t, "sign", "-dir", dir, csr)
	if code != 1 || !strings.Contains(errs, "chmod 600") {
		t.Fatalf("sign with a 0644 key: %d %q", code, errs)
	}
}

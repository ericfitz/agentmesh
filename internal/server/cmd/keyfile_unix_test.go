//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertOwnerOnlyKey(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("%s has mode %#o, want 0600", path, got)
	}
}

func TestReadOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.pem")
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := readOwnerOnly(path)
		if err == nil || !strings.Contains(err.Error(), "chmod 600 "+path) || !strings.Contains(err.Error(), path) {
			t.Errorf("mode %#o: err = %v, want a refusal naming the path and chmod 600", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		b, err := readOwnerOnly(path)
		if err != nil || string(b) != "secret" {
			t.Errorf("mode %#o: %q, %v", mode, b, err)
		}
	}
	if _, err := readOwnerOnly(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: err = %v", err)
	}
	if _, err := readOwnerOnly(filepath.Join(dir, "absent")); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Errorf("a missing file: err = %v", err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if b, err := readOwnerOnly(link); err != nil || string(b) != "secret" {
		t.Errorf("a symlink to an owner-only file: %q, %v", b, err)
	}
}

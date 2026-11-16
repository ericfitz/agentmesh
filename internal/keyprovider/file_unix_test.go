//go:build !windows

package keyprovider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateKeyFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "int.key")
	if err := CreateKeyFile(path, noRestrict); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

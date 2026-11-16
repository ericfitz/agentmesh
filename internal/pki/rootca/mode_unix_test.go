//go:build !windows

package rootca

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRootKeyMode(t *testing.T) {
	dir := newDir(t)
	fi, err := os.Stat(filepath.Join(dir, "root.key"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("root.key mode %o, want 600", got)
	}
}

//go:build unix

package cmd

import (
	"os"
	"strings"
	"testing"
)

// A key file that other accounts can read stops the start with exit 2 naming
// the file and the fix, before the Store is opened (ADR 0019 section 4.15).
func TestStartupKeyFileNotOwnerOnly(t *testing.T) {
	e := newStartEnv(t)
	if err := os.Chmod(e.f.KeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs := start(e.args(e.trustSets()...))
	if code != 2 || !strings.Contains(errs, e.f.KeyFile) || !strings.Contains(errs, "chmod 600") {
		t.Fatalf("exit %d, stderr %q; want 2 naming the key file and chmod 600", code, errs)
	}
	if strings.Contains(out, "listening") {
		t.Fatalf("a refused start printed %q", out)
	}
}

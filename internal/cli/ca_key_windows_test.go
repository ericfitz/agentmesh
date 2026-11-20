//go:build windows

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/fileacl/acltest"
)

// Windows proof of issue #44: `ca init` leaves root.key with an owner-only
// DACL (the real fileacl.OwnerOnly, no seam), and a root.key opened up to
// Everyone stops `ca sign`. Runs under `make windows-test`.
func TestCAInitRootKeyOwnerOnlyWindows(t *testing.T) {
	dir := caInit(t)
	acltest.AssertOwnerOnly(t, filepath.Join(dir, "root.key"))
}

func TestCASignRefusesExposedKeyWindows(t *testing.T) {
	dir := caInit(t)
	key := filepath.Join(dir, "root.key")
	acltest.GrantEveryone(t, key)
	csr := caWrite(t, t.TempDir(), "a.csr", pkiCSR(t))
	code, _, errs := runCA(t, "sign", "-dir", dir, csr)
	if code != 1 || !containsAll(errs, "S-1-1-0", "icacls") {
		t.Fatalf("sign with Everyone on root.key: %d %q", code, errs)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}

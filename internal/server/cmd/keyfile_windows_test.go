//go:build windows

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/fileacl/acltest"
)

func assertOwnerOnlyKey(t *testing.T, path string) {
	t.Helper()
	acltest.AssertOwnerOnly(t, path)
}

func TestReadOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.pem")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	acltest.GrantEveryone(t, path)
	if _, err := readOwnerOnly(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("an ACL that grants another account: err = %v, want a refusal naming the path", err)
	}
	if _, err := readOwnerOnly(dir); err == nil {
		t.Fatal("a directory was read")
	}
}

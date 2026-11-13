package trust

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ericfitz/agentmesh/internal/pki"
)

func thumb(c testCA) string { return pki.Thumbprint(c.root.Raw) }

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// mkParentFile makes path a regular file (its parents created).
func mkParentFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("not a directory"), 0o600)
}

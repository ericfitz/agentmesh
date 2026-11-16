package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/ericfitz/agentmesh/internal/fileacl"
)

// readOwnerOnly reads a regular file that only its owner can read or write:
// Unix mode 0600 or narrower, fileacl.CheckOwnerOnly on Windows (where a mode
// means nothing). A symlink is followed and the target is checked. The error
// names the path and the fix.
func readOwnerOnly(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS == "windows" {
		if err := fileacl.CheckOwnerOnly(path); err != nil {
			if errors.Is(err, fileacl.ErrExposed) {
				return nil, fmt.Errorf("%s: %w; restrict it with: %s", path, err, fileacl.WindowsFix(path))
			}
			return nil, fmt.Errorf("check %s: %w", path, err)
		}
	} else if perm := fi.Mode().Perm(); perm&^0o600 != 0 {
		return nil, fmt.Errorf("%s has mode %#o, which other accounts can read or write, and holds a private key; chmod 600 %s", path, perm, path)
	}
	return io.ReadAll(f)
}

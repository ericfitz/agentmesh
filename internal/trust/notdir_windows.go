//go:build windows

package trust

import "syscall"

// ERROR_PATH_NOT_FOUND: a component of the path is a file.
func isNotDir(err error) bool { return err == syscall.Errno(3) || err == syscall.ENOTDIR }

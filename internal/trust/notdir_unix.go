//go:build !windows

package trust

import "syscall"

func isNotDir(err error) bool { return err == syscall.ENOTDIR }

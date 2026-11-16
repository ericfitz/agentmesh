package rootca

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// lockWait is how long a command waits for dir/lock (Plan ruling 5); a test
// shortens it.
var lockWait = 10 * time.Second

const lockPoll = 20 * time.Millisecond

// lockDir takes the root tool's lock: the file dir/lock, created exclusively
// and removed by the returned function. A killed run can leave the file; the
// error then names it.
func lockDir(dir string) (unlock func(), err error) {
	path := filepath.Join(dir, "lock")
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("rootca: take the lock %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("rootca: %s is held by another command; remove it if no agentmesh ca command is running", path)
		}
		time.Sleep(lockPoll)
	}
}

package mcpcli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A result that cannot be written to standard output is exit 1 with the cause
// on standard error, never exit 0 (issue #44).
func TestResultWriteFailureIsExit1(t *testing.T) {
	environ, _ := testEnviron(t)
	t.Chdir(t.TempDir())
	for _, args := range [][]string{
		{"version"},
		{"help"},
		{"help", "register"},
		{"config", "-server", "https://h:1", "-identity", "pat"},
	} {
		var e bytes.Buffer
		code := Main(context.Background(), args, environ, strings.NewReader(""), failWriter{}, &e)
		if code != 1 || !strings.Contains(e.String(), "broken pipe") {
			t.Errorf("%v: code %d, stderr %q", args, code, e.String())
		}
	}
}

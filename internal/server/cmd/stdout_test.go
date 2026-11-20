package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

type brokenStdout struct{}

func (brokenStdout) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func runBroken(args ...string) (int, string) {
	var e bytes.Buffer
	code := RunAdmin(context.Background(), args, nil, brokenStdout{}, &e)
	return code, e.String()
}

// A host command whose result cannot be written exits 1 with the cause on
// standard error; the enrollment token, shown once, says what was committed
// and how to recover (issue #44).
func TestEnrollmentCreateStdoutFailure(t *testing.T) {
	e := newAdminEnv(t)
	code, errOut := runBroken("-sqlite", e.file, "enrollment", "create")
	if code != 1 || !strings.Contains(errOut, "broken pipe") || !strings.Contains(errOut, "WAS created") || !strings.Contains(errOut, "enrollment revoke") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	// The recovery works: the token is listed.
	if code, out, errs := e.run("enrollment", "list"); code != 0 || strings.TrimSpace(out) == "" {
		t.Fatalf("list = %d %q %q", code, out, errs)
	}
}

func TestCACsrStdoutFailure(t *testing.T) {
	e := newCAEnv(t)
	key := filepath.Join(t.TempDir(), "new.key")
	args := append([]string{"-sqlite", e.file}, e.settings("intermediate_key_file="+key)...)
	code, errOut := runBroken(append(args, "ca", "csr")...)
	if code != 1 || !strings.Contains(errOut, "broken pipe") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}

func TestHostCommandsStdoutFailure(t *testing.T) {
	e := newCAEnv(t)
	base := []string{"-sqlite", e.file}
	if code, _, errs := e.run("enrollment", "create"); code != 0 { // so that list has a row
		t.Fatal(errs)
	}
	ca := append(append([]string{}, base...), e.settings("intermediate_key_file="+e.f.KeyFile)...)
	for _, c := range []struct {
		name string
		args []string
	}{
		{"create-identity", append(append([]string{}, base...), "create-identity", "kim")},
		{"users add", append(append([]string{}, base...), "users", "add", "-identity", "kim")},
		{"reset-credential", append(append([]string{}, base...), "reset-credential", "kim")},
		{"enrollment list", append(append([]string{}, base...), "enrollment", "list")},
		{"signing-key list", append(ca, "signing-key", "list")},
		{"ca status", append(ca, "ca", "status")},
	} {
		if code, errOut := runBroken(c.args...); code != 1 || !strings.Contains(errOut, "broken pipe") {
			t.Errorf("%s: exit %d, stderr %q", c.name, code, errOut)
		}
	}
}

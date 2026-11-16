package mcpcli

import (
	"github.com/ericfitz/agentmesh/internal/client"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isAbs(p string) bool { return filepath.IsAbs(p) }

// open note: mcp-only-client 13
func TestEnrollmentTokenSources(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tok")
	write := func(body string) string {
		t.Helper()
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	env := []string{"AGENTMESH_ENROLLMENT_TOKEN=abe_env"}

	if got, err := enrollmentToken("abe_flag", "", env); err != nil || got != "abe_flag" {
		t.Errorf("flag over variable: %q, %v", got, err)
	}
	if got, err := enrollmentToken("", write("abe_file\n"), env); err != nil || got != "abe_file" {
		t.Errorf("file over variable: %q, %v", got, err)
	}
	if got, err := enrollmentToken("", write("  abe_x\n"), nil); err != nil || got != "abe_x" {
		t.Errorf("trimmed file: %q, %v", got, err)
	}
	if got, err := enrollmentToken("", "", env); err != nil || got != "abe_env" {
		t.Errorf("variable: %q, %v", got, err)
	}
	if got, err := enrollmentToken("", "", nil); err != nil || got != "" {
		t.Errorf("none: %q, %v", got, err)
	}
	if _, err := enrollmentToken("abe_flag", write("abe_file"), env); err == nil {
		t.Error("both flags: want an error")
	}
	// write reuses one path, so the empty case gets a file of its own.
	emptyFile := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyFile, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ path, msg string }{
		"empty":     {emptyFile, "is empty"},
		"directory": {dir, ""},
		"too big":   {write(strings.Repeat("A", 4097)), ""},
		"missing":   {filepath.Join(dir, "nope"), ""},
	} {
		_, err := enrollmentToken("", c.path, env)
		if err == nil || !strings.Contains(err.Error(), c.path) || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: err %v, want one naming %s containing %q", name, err, c.path, c.msg)
		}
	}
	if got, err := enrollmentToken("", write(strings.Repeat("A", 4096)), nil); err != nil || len(got) != 4096 {
		t.Errorf("4096-byte file: len %d, %v", len(got), err)
	}
}

func TestTrustFlagsAndEnv(t *testing.T) {
	const thumbA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const thumbB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	opts := func(args, env []string) (client.Options, int, string) {
		var errb strings.Builder
		o, code := serveOptions(args, env, &errb)
		return o.Client, code, errb.String()
	}
	// Variables alone.
	o, code, _ := opts(nil, []string{"AGENTMESH_INSECURE_HTTP=1", "AGENTMESH_ROOT_THUMBPRINT=" + thumbA, "AGENTMESH_INSTALLATION=prod"})
	if code != -1 || !o.InsecureHTTP || o.RootThumbprint != thumbA || o.Installation != "prod" {
		t.Errorf("variables: code %d, %+v", code, o)
	}
	// Flags alone.
	o, code, _ = opts([]string{"-insecure-http", "-root-thumbprint", thumbA, "-installation", "dev"}, nil)
	if code != -1 || !o.InsecureHTTP || o.RootThumbprint != thumbA || o.Installation != "dev" {
		t.Errorf("flags: code %d, %+v", code, o)
	}
	// A flag wins over its variable.
	o, code, _ = opts([]string{"-root-thumbprint", thumbB, "-installation", "dev"}, []string{"AGENTMESH_ROOT_THUMBPRINT=" + thumbA, "AGENTMESH_INSTALLATION=prod"})
	if code != -1 || o.RootThumbprint != thumbB || o.Installation != "dev" {
		t.Errorf("flag over variable: code %d, %+v", code, o)
	}
	// An empty variable is unset; unset leaves everything off.
	o, code, _ = opts(nil, []string{"AGENTMESH_INSECURE_HTTP="})
	if code != -1 || o.InsecureHTTP {
		t.Errorf("empty variable: code %d, %+v", code, o)
	}
	// Only 1 and the empty string are accepted for the switch.
	for _, v := range []string{"true", "0", "yes", "TRUE", " 1"} {
		_, code, errs := opts(nil, []string{"AGENTMESH_INSECURE_HTTP=" + v})
		if code != 2 || !strings.Contains(errs, "AGENTMESH_INSECURE_HTTP") {
			t.Errorf("AGENTMESH_INSECURE_HTTP=%q: code %d, stderr %q", v, code, errs)
		}
	}
}

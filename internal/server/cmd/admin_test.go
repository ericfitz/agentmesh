package cmd

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/identities"
	"github.com/ericfitz/agentmesh/internal/core/scopes"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/store/sqlite"
)

// adminEnv is one SQLite file per test plus a way to run RunAdmin against it.
type adminEnv struct {
	t    *testing.T
	file string
}

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	return &adminEnv{t: t, file: filepath.Join(t.TempDir(), "bus.db")}
}

// run executes RunAdmin with -sqlite <file> and the given arguments, with a
// nil environment.
func (e *adminEnv) run(args ...string) (code int, out, errOut string) {
	e.t.Helper()
	return e.runEnv(nil, append([]string{"-sqlite", e.file}, args...)...)
}

func (e *adminEnv) runEnv(environ []string, args ...string) (code int, out, errOut string) {
	e.t.Helper()
	var o, er bytes.Buffer
	code = RunAdmin(context.Background(), args, environ, &o, &er)
	return code, o.String(), er.String()
}

// service opens a second handle on the same file.
func (e *adminEnv) service() (identities.Service, store.Store) {
	e.t.Helper()
	st, err := sqlite.Open(context.Background(), e.file, sqlite.Options{})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = st.Close() })
	c, err := core.New(st, core.Defaults(), core.Options{})
	if err != nil {
		e.t.Fatal(err)
	}
	return identities.Service{Core: c}, st
}

func readStore[T any](t *testing.T, st store.Store, f func(context.Context, store.Tx) (T, error)) T {
	t.Helper()
	var out T
	err := st.Read(context.Background(), func(ctx context.Context, tx store.Tx) error {
		var err error
		out, err = f(ctx, tx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAdminUsersAdminsCommands(t *testing.T) {
	e := newAdminEnv(t)
	if code, _, errOut := e.run("admins", "add", "-identity", "pat"); code != 1 || !strings.Contains(errOut, "register it first") {
		t.Fatalf("admins add before pat exists: code %d stderr %q", code, errOut)
	}
	if code, _, errOut := e.run("create-identity", "pat"); code != 0 {
		t.Fatalf("create-identity: %d %s", code, errOut)
	}
	_, st := e.service()
	isAdmin := func() bool {
		return readStore(t, st, func(ctx context.Context, tx store.Tx) (bool, error) {
			id, err := tx.Identity(ctx, "pat")
			return id.Admin, err
		})
	}
	for i, want := range []string{"added", "already present"} {
		code, out, errOut := e.run("admins", "add", "-identity", "pat")
		if code != 0 || strings.TrimSpace(out) != want || !isAdmin() {
			t.Fatalf("admins add %d: code %d out %q stderr %q admin %v", i, code, out, errOut, isAdmin())
		}
	}
	if code, out, _ := e.run("admins", "list"); code != 0 || strings.TrimSpace(out) != "{identity: pat}" {
		t.Fatalf("admins list: %d %q", code, out)
	}
	if code, out, _ := e.run("users", "list"); code != 0 || out != "" {
		t.Fatalf("users list: %d %q", code, out)
	}
	// No issuer is configured yet: a well-formed claim add is a service error.
	if code, _, errOut := e.run("users", "add", "-issuer", "corp", "-group", "x"); code != 1 || !strings.Contains(errOut, "unknown issuer") {
		t.Fatalf("users add group: code %d stderr %q", code, errOut)
	}
	for _, bad := range [][]string{
		{"admins", "add", "-group", "x"},
		{"admins", "add", "-identity", "pat", "-email", "a@b"},
		{"admins", "add", "-identity", "pat", "-issuer", "corp"},
		{"admins", "add"},
		{"admins", "add", "-email", "nope", "-issuer", "corp"},
		{"admins", "frob"},
		{"admins"},
		{"admins", "list", "extra"},
		{"admins", "list", "-identity", "pat"},
	} {
		if code, _, errOut := e.run(bad...); code != 2 || errOut == "" {
			t.Errorf("%v: code %d stderr %q, want 2 with a message", bad, code, errOut)
		}
	}
	for i, want := range []string{"removed", "not present"} {
		code, out, _ := e.run("admins", "remove", "-identity", "pat")
		if code != 0 || strings.TrimSpace(out) != want || isAdmin() {
			t.Fatalf("admins remove %d: code %d out %q admin %v", i, code, out, isAdmin())
		}
	}
}

func TestAdminMakeAdminReplaced(t *testing.T) {
	e := newAdminEnv(t)
	code, out, errOut := e.run("make-admin", "pat")
	if code != 2 || out != "" || !strings.Contains(errOut, "make-admin was replaced by: admins add -identity NAME (admins remove -identity NAME)") {
		t.Fatalf("make-admin: code %d out %q stderr %q", code, out, errOut)
	}
}

func TestAdminResetCredential(t *testing.T) {
	e := newAdminEnv(t)
	svc, st := e.service()
	if err := svc.RegisterLocal(context.Background(), "pat"); err != nil {
		t.Fatal(err)
	}

	code, out, _ := e.run("reset-credential", "pat")
	if code != 0 || !strings.Contains(out, "0 credential(s)") {
		t.Fatalf("reset-credential (none): code %d out %q", code, out)
	}
	err := st.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error {
		return tx.PutPublicKey(ctx, store.PublicKey{Identity: "pat", KID: "k1", Algorithm: "EdDSA", Key: []byte{1}, CreatedAt: 1})
	})
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ = e.run("reset-credential", "pat")
	if code != 0 || !strings.Contains(out, "1 credential(s)") {
		t.Fatalf("reset-credential (one): code %d out %q", code, out)
	}
	if code, _, errOut := e.run("reset-credential", "ghost"); code != 1 || !strings.Contains(errOut, "register it first") {
		t.Fatalf("reset-credential of an unknown name: code %d stderr %q", code, errOut)
	}
}

func TestAdminCreateIdentity(t *testing.T) {
	e := newAdminEnv(t)
	code, out, _ := e.run("create-identity", "kim")
	if code != 0 || strings.TrimSpace(out) != "kim created" {
		t.Fatalf("first create: code %d out %q", code, out)
	}
	code, out, _ = e.run("create-identity", "kim")
	if code != 0 || strings.TrimSpace(out) != "kim already exists" {
		t.Fatalf("second create: code %d out %q", code, out)
	}
	svc, st := e.service()
	_ = svc
	id := readStore(t, st, func(ctx context.Context, tx store.Tx) (store.Identity, error) { return tx.Identity(ctx, "kim") })
	if id.Admin {
		t.Fatal("create-identity set the administrator flag")
	}
	n := readStore(t, st, func(ctx context.Context, tx store.Tx) (int, error) {
		gen, err := tx.ChannelByName(ctx, "general")
		if err != nil {
			return 0, err
		}
		subs, err := tx.Subscriptions(ctx, "kim")
		if err != nil {
			return 0, err
		}
		n := 0
		for _, s := range subs {
			if s.ChannelID == gen.ID {
				n++
			}
		}
		return n, nil
	})
	if n != 1 {
		t.Fatalf("kim has %d general subscriptions, want 1", n)
	}

	code, _, errOut := e.run("create-identity")
	if code != 2 || !strings.Contains(errOut, "keyless") || !strings.Contains(errOut, "enrollment token") {
		t.Fatalf("create-identity without a name: code %d stderr %q", code, errOut)
	}
	// A reserved or malformed name is refused by the Store rule, not accepted.
	if code, _, _ := e.run("create-identity", "everyone"); code == 0 {
		t.Fatal("create-identity accepted the reserved name everyone")
	}
}

var (
	tokenRE = regexp.MustCompile(`(?m)^token: (abe_\S+)$`)
	infoRE  = regexp.MustCompile(`(?m)^id: (\S+) identity: (\S+) expires: (\S+) uses: (\d+)$`)
)

func TestAdminEnrollmentLifecycle(t *testing.T) {
	e := newAdminEnv(t)
	code, out, errOut := e.run("enrollment", "create")
	if code != 0 {
		t.Fatalf("create: code %d stderr %q", code, errOut)
	}
	if !tokenRE.MatchString(out) {
		t.Fatalf("no token line in %q", out)
	}
	m := infoRE.FindStringSubmatch(out)
	if m == nil || m[2] != "any" || m[4] != "1" {
		t.Fatalf("info line %q (match %v)", out, m)
	}
	id1 := m[1]

	code, out, _ = e.run("enrollment", "list")
	if code != 0 || !strings.HasPrefix(out, id1+" any ") || strings.Contains(out, "expired") {
		t.Fatalf("list: code %d out %q", code, out)
	}

	code, out, errOut = e.run("enrollment", "create", "-uses", "3", "-expires", "1h", "-identity", "kim")
	if code != 0 {
		t.Fatalf("create with flags: code %d stderr %q", code, errOut)
	}
	m = infoRE.FindStringSubmatch(out)
	if m == nil || m[2] != "kim" || m[4] != "3" {
		t.Fatalf("info line %q", out)
	}
	id2 := m[1]
	_, out, _ = e.run("enrollment", "list")
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 2 {
		t.Fatalf("list has %d lines: %q", len(lines), out)
	}

	code, out, _ = e.run("enrollment", "revoke", id1)
	if code != 0 || strings.TrimSpace(out) != id1+" revoked" {
		t.Fatalf("revoke: code %d out %q", code, out)
	}
	if code, _, _ := e.run("enrollment", "revoke", id1); code != 1 {
		t.Fatalf("second revoke: code %d, want 1", code)
	}
	_, out, _ = e.run("enrollment", "list")
	if strings.Contains(out, id1) || !strings.Contains(out, id2) {
		t.Fatalf("list after revoke: %q", out)
	}

	for _, bad := range [][]string{
		{"enrollment"},
		{"enrollment", "frobnicate"},
		{"enrollment", "create", "-uses", "0"},
		{"enrollment", "create", "-expires", "-1h"},
		{"enrollment", "create", "-expires", "soon"},
		{"enrollment", "create", "extra"},
		{"enrollment", "list", "extra"},
		{"enrollment", "revoke"},
		{"nonsense"},
		{"signing-key", "create", "x"},
	} {
		if code, _, errOut := e.run(bad...); code != 2 || errOut == "" {
			t.Errorf("%v: code %d stderr %q, want 2 with a message", bad, code, errOut)
		}
	}
	if _, _, errOut := e.run("nonsense"); !strings.Contains(errOut, "users and admins") {
		t.Errorf("unknown subcommand message does not list the subcommands: %q", errOut)
	}
	if code, _, _ := e.runEnv(nil, "-sqlite", e.file); code != 2 {
		t.Errorf("no subcommand: code %d, want 2", code)
	}
}

func TestAdminEnrollmentListMarksExpired(t *testing.T) {
	e := newAdminEnv(t)
	svc, st := e.service()
	_ = svc
	err := st.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error {
		return tx.PutEnrollmentToken(ctx, store.EnrollmentToken{ID: "dead", TokenHash: "h", ExpiresAt: 1, UsesLeft: 1, CreatedAt: 1})
	})
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ := e.run("enrollment", "list")
	if code != 0 || !strings.HasSuffix(strings.TrimSpace(out), " expired") {
		t.Fatalf("list: code %d out %q", code, out)
	}
}

func TestAdminWorksWithoutServer(t *testing.T) {
	e := newAdminEnv(t)
	cfgPath := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(cfgPath, []byte(`{"listen": "nonsense", "registration": "open"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := e.run("-config", cfgPath, "create-identity", "a"); code != 0 {
		t.Fatalf("config with a nonsense listen: code %d stderr %q", code, errOut)
	}
	if code, _, errOut := e.run("-set", "listen=nonsense", "-set", "registration=enrollment", "create-identity", "b"); code != 0 {
		t.Fatalf("-set listen/registration: code %d stderr %q", code, errOut)
	}
	if code, _, errOut := e.runEnv([]string{"AGENTMESH_SERVER_LISTEN=nonsense"}, "-sqlite", e.file, "create-identity", "c"); code != 0 {
		t.Fatalf("environment listen: code %d stderr %q", code, errOut)
	}
	// Syntax of registration is still judged, as for the server.
	if code, _, errOut := e.run("-set", "registration=bogus", "create-identity", "d"); code != 2 || !strings.Contains(errOut, "registration") {
		t.Fatalf("bad registration: code %d stderr %q", code, errOut)
	}
	for _, fl := range [][]string{{"-listen", "127.0.0.1:0"}, {"-registration", "open"}} {
		args := append([]string{"-sqlite", e.file}, fl...)
		args = append(args, "create-identity", "e")
		if code, _, _ := e.runEnv(nil, args...); code != 2 {
			t.Errorf("%v: code %d, want 2 (unknown flag)", fl, code)
		}
	}
}

func TestAdminFlagSet(t *testing.T) {
	e := newAdminEnv(t)
	code, _, errOut := e.run("-set", "colour=1", "create-identity", "a")
	if code != 2 || !strings.Contains(errOut, "colour") || !strings.Contains(errOut, "registration") {
		t.Fatalf("-set colour: code %d stderr %q", code, errOut)
	}
	if code, _, _ := e.run("-set", "nonsense", "create-identity", "a"); code != 2 {
		t.Fatalf("-set without '=': code %d, want 2", code)
	}
	missing := filepath.Join(t.TempDir(), "missing.json")
	if code, _, _ := e.run("-config", missing, "create-identity", "a"); code != 2 {
		t.Fatalf("missing -config: code %d, want 2", code)
	}
	code, _, errOut = e.runEnv(nil, "-sqlite", e.file, "-postgres", "postgres://x", "create-identity", "a")
	if code != 2 || !strings.Contains(errOut, "exactly one") {
		t.Fatalf("both stores: code %d stderr %q", code, errOut)
	}
	code, _, errOut = e.runEnv(nil, "create-identity", "a")
	if code != 2 || !strings.Contains(errOut, "exactly one") {
		t.Fatalf("no store: code %d stderr %q", code, errOut)
	}
	code, out, errOut := e.runEnv([]string{"AGENTMESH_SERVER_SQLITE=" + e.file}, "create-identity", "a")
	if code != 0 || !strings.Contains(out, "a created") {
		t.Fatalf("store from the environment: code %d out %q stderr %q", code, out, errOut)
	}
	code, _, errOut = e.runEnv([]string{"AGENTMESH_SERVER_SQLITE=" + e.file, "AGENTMESH_SERVER_COLOUR=1"}, "create-identity", "b")
	if code != 2 || !strings.Contains(errOut, "colour") {
		t.Fatalf("unknown environment setting: code %d stderr %q", code, errOut)
	}
	// -set overrides the environment; the -sqlite flag overrides both.
	other := filepath.Join(t.TempDir(), "other.db")
	if code, _, errOut := e.runEnv([]string{"AGENTMESH_SERVER_SQLITE=" + e.file}, "-sqlite", other, "create-identity", "z"); code != 0 {
		t.Fatalf("flag over environment: code %d stderr %q", code, errOut)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("the -sqlite flag did not win: %v", err)
	}
	// -h prints usage naming every setting and exits 0.
	var o, er bytes.Buffer
	if code := RunAdmin(context.Background(), []string{"-h"}, nil, &o, &er); code != 0 || !strings.Contains(o.String(), "receive_max_count") {
		t.Fatalf("-h: code %d out %q", code, o.String())
	}
	// A store that cannot open is a runtime error (1), not a flag error.
	bad := filepath.Join(t.TempDir(), "no-such-dir", "x.db")
	if code, _, _ := e.runEnv(nil, "-sqlite", bad, "create-identity", "a"); code != 1 {
		t.Fatalf("unopenable store: code %d, want 1", code)
	}
}

func TestAdminCreateHuman(t *testing.T) {
	e := newAdminEnv(t)
	code, out, _ := e.run("create-human", "Eric@Corp.Example")
	if code != 0 || strings.TrimSpace(out) != "eric@corp.example created" {
		t.Fatalf("first create: code %d out %q", code, out)
	}
	code, out, _ = e.run("create-human", "eric@corp.example")
	if code != 0 || strings.TrimSpace(out) != "eric@corp.example already exists" {
		t.Fatalf("second create: code %d out %q", code, out)
	}
	_, st := e.service()
	id := readStore(t, st, func(ctx context.Context, tx store.Tx) (store.Identity, error) {
		return tx.Identity(ctx, "eric@corp.example")
	})
	if id.Kind != store.IdentityHuman || id.Admin {
		t.Fatalf("identity = %+v", id)
	}
	code, _, errOut := e.run("create-human", "bad")
	if code != 1 || !strings.Contains(errOut, "one '@'") {
		t.Fatalf("create-human bad: code %d stderr %q", code, errOut)
	}
	if code, _, _ := e.run("create-human"); code != 2 {
		t.Fatalf("create-human without an argument: code %d, want 2", code)
	}
	if code, _, _ := e.run("create-identity", "kim@corp.example"); code != 0 {
		t.Fatal("create-identity failed")
	}
	if code, _, errOut := e.run("create-human", "kim@corp.example"); code != 1 || !strings.Contains(errOut, "is an agent") {
		t.Fatalf("create-human over an agent: code %d stderr %q", code, errOut)
	}
}

// TestAdminUsersAddKnownIssuer: the issuers entry names are the references'
// issuer handles (spec 5.1); an unconfigured name is refused and the error
// names the configured ones.
func TestAdminUsersAddKnownIssuer(t *testing.T) {
	e := newAdminEnv(t)
	issuers := `[{"name":"corp","issuer":"https://idp.example","jwks_uri":"https://idp.example/jwks","audience":"agentmesh"}]`
	set := []string{"-set", "issuers=" + issuers}
	run := func(args ...string) (int, string, string) {
		return e.run(append(set, args...)...)
	}
	for i, want := range []string{"added", "already present"} {
		code, out, errOut := run("users", "add", "-issuer", "corp", "-group", "pai-users")
		if code != 0 || strings.TrimSpace(out) != want {
			t.Fatalf("users add %d: code %d out %q stderr %q, want %q", i, code, out, errOut, want)
		}
	}
	code, _, errOut := run("users", "add", "-issuer", "nope", "-group", "pai-users")
	if code != 1 || !strings.Contains(errOut, "unknown issuer") || !strings.Contains(errOut, "nope") || !strings.Contains(errOut, "configured: corp") {
		t.Fatalf("unknown issuer: code %d stderr %q, want exit 1 naming corp", code, errOut)
	}
}

func TestAdminCreateScopedIdentity(t *testing.T) {
	e := newAdminEnv(t)
	// The first host command creates the schema and the admin.
	if code, _, errOut := e.run("create-identity", "root"); code != 0 {
		t.Fatalf("create-identity root: %d %s", code, errOut)
	}
	if code, _, errOut := e.run("admins", "add", "-identity", "root"); code != 0 {
		t.Fatalf("admins add: %d %s", code, errOut)
	}
	svc, st := e.service()
	if _, err := (scopes.Service{Core: svc.Core}).Create(context.Background(), "root", bus.CreateScopeInput{Name: "job1"}); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := e.run("create-identity", "job1-coder", "-scope", "job1")
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if code != 0 || len(lines) != 3 || lines[0] != "job1-coder created in scope job1" ||
		!regexp.MustCompile(`^token: abe_\S+$`).MatchString(lines[1]) ||
		!regexp.MustCompile(`^expires: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`).MatchString(lines[2]) {
		t.Fatalf("scoped create: code %d out %q stderr %q", code, out, errOut)
	}
	id := readStore(t, st, func(ctx context.Context, tx store.Tx) (store.Identity, error) { return tx.Identity(ctx, "job1-coder") })
	if id.Scope != "job1" {
		t.Fatalf("row scope %q", id.Scope)
	}
	first := strings.TrimPrefix(lines[1], "token: ")

	// A second run: "already exists in", a different token.
	code, out, _ = e.run("create-identity", "-scope", "job1", "job1-coder")
	lines = strings.Split(strings.TrimRight(out, "\n"), "\n")
	if code != 0 || len(lines) != 3 || lines[0] != "job1-coder already exists in scope job1" || strings.TrimPrefix(lines[1], "token: ") == first {
		t.Fatalf("scoped create again: code %d out %q", code, out)
	}

	// An unknown scope names the scope; nothing is created.
	code, out, errOut = e.run("create-identity", "x-a", "-scope", "nope")
	if code != 1 || out != "" || !strings.Contains(errOut, "nope") || !strings.Contains(errOut, "does not exist") {
		t.Fatalf("unknown scope: code %d out %q stderr %q", code, out, errOut)
	}

	// Without -scope the output is unchanged.
	code, out, _ = e.run("create-identity", "pat")
	if code != 0 || out != "pat created\n" {
		t.Fatalf("plain create: code %d out %q", code, out)
	}
}

// skEnv is a caEnv with the intermediate installed, running `signing-key`.
type skEnv struct{ *caEnv }

func newSKEnv(t *testing.T) *skEnv {
	t.Helper()
	e := &skEnv{newCAEnv(t)}
	if code, _, errOut := e.ca("install", e.f.CertFile); code != 0 {
		t.Fatalf("install: %d %s", code, errOut)
	}
	return e
}

func (e *skEnv) sk(args ...string) (int, string, string) {
	e.t.Helper()
	all := append(e.settings("intermediate_key_file="+e.f.KeyFile), "signing-key")
	return e.run(append(all, args...)...)
}

// leaf stores a leaf of the fixture's key, valid from now for a day.
func (e *skEnv) leaf() *x509.Certificate {
	e.t.Helper()
	c, _ := e.core()
	_, cert := e.f.Leaf(e.t, c, time.Now(), 24*time.Hour)
	return cert
}

func tp(c *x509.Certificate) string { return pki.Thumbprint(c.Raw) }

func TestSigningKeyList(t *testing.T) {
	e := newSKEnv(t)
	code, out, errOut := e.sk("list")
	wantExit(t, code, 0, errOut)
	if want := fmt.Sprintf("trust-number %d\n", e.trustNumber()); out != want {
		t.Fatalf("no leaves: %q, want %q", out, want)
	}
	a, b := e.leaf(), e.leaf()
	code, out, errOut = e.sk("list")
	wantExit(t, code, 0, errOut)
	line := func(c *x509.Certificate, state string) string {
		return fmt.Sprintf("leaf %s serial %s %s %s %s", tp(c), pki.SerialText(c.SerialNumber),
			c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), state)
	}
	if want := line(a, "other") + "\n" + line(b, "other") + "\n" + fmt.Sprintf("trust-number %d\n", e.trustNumber()); out != want {
		t.Fatalf("list:\n%s\nwant\n%s", out, want)
	}
	// A revoked leaf is listed last, as revoked.
	if code, _, errOut := e.sk("revoke", "-cert", certFile(t, a)); code != 0 {
		t.Fatalf("revoke: %d %s", code, errOut)
	}
	_, out, _ = e.sk("list")
	if want := line(b, "other") + "\n" + line(a, "revoked") + "\n" + fmt.Sprintf("trust-number %d\n", e.trustNumber()); out != want {
		t.Fatalf("list after revoke:\n%s\nwant\n%s", out, want)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("list leaks a key")
	}
}

func TestSigningKeyRotate(t *testing.T) {
	e := newSKEnv(t)
	// Nothing to revoke: the trust number alone, exit 0, nothing written.
	n0 := e.trustNumber()
	code, out, errOut := e.sk("rotate")
	wantExit(t, code, 0, errOut)
	if want := fmt.Sprintf("trust-number %d\n", n0); out != want || e.trustNumber() != n0 {
		t.Fatalf("rotate with no leaves: %q (number %d -> %d)", out, n0, e.trustNumber())
	}

	a, b := e.leaf(), e.leaf()
	code, out, errOut = e.sk("rotate")
	wantExit(t, code, 0, errOut)
	n1 := e.trustNumber()
	want := fmt.Sprintf("revoked %s human-messages 0\nrevoked %s human-messages 0\ntrust-number %d\n", tp(a), tp(b), n1)
	if out != want || n1 <= n0 || errOut != "" {
		t.Fatalf("rotate:\n%s\nwant\n%s (number %d -> %d, stderr %q)", out, want, n0, n1, errOut)
	}
	if _, l, _ := e.sk("list"); strings.Count(l, " revoked\n") != 2 {
		t.Fatalf("list after rotate: %q", l)
	}

	// A second run revokes only the leaves issued since.
	c := e.leaf()
	code, out, errOut = e.sk("rotate")
	wantExit(t, code, 0, errOut)
	n2 := e.trustNumber()
	if want := fmt.Sprintf("revoked %s human-messages 0\ntrust-number %d\n", tp(c), n2); out != want || n2 <= n1 {
		t.Fatalf("second rotate: %q, want %q (number %d -> %d)", out, want, n1, n2)
	}
	// And with none issued since: the trust number alone, unchanged.
	code, out, errOut = e.sk("rotate")
	wantExit(t, code, 0, errOut)
	if want := fmt.Sprintf("trust-number %d\n", n2); out != want || e.trustNumber() != n2 {
		t.Fatalf("third rotate: %q, want %q", out, want)
	}
}

// A leaf under another intermediate key of the installation is not covered:
// its thumbprint goes to standard error and nothing else changes for it.
func TestSigningKeyRotateNotCovered(t *testing.T) {
	e := newSKEnv(t)
	k2 := newP256(t)
	inter2 := craft(t, e.f, &k2.PublicKey, nil)
	_, st := e.core()
	foreign := leafUnder(t, inter2, k2, time.Now(), 24*time.Hour)
	err := st.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error {
		if _, err := tx.PutTrustCertificate(ctx, store.TrustCertificate{
			Kind: store.TrustIntermediate, Thumbprint: tp(inter2), DER: inter2.Raw,
			NotAfter: inter2.NotAfter.UnixMilli(), CreatedAt: time.Now().UnixMilli(),
		}); err != nil {
			return err
		}
		_, err := tx.PutTrustCertificate(ctx, store.TrustCertificate{
			Kind: store.TrustLeaf, Thumbprint: tp(foreign), DER: foreign.Raw,
			IssuerKey: pki.KeyID(inter2.SubjectKeyId), NotAfter: foreign.NotAfter.UnixMilli(), CreatedAt: time.Now().UnixMilli(),
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	mine := e.leaf()
	code, out, errOut := e.sk("rotate")
	wantExit(t, code, 0, errOut)
	if errOut != "not-covered "+tp(foreign)+"\n" {
		t.Fatalf("stderr %q, want the foreign leaf's thumbprint", errOut)
	}
	if !strings.HasPrefix(out, "revoked "+tp(mine)+" human-messages 0\n") || strings.Contains(out, tp(foreign)) {
		t.Fatalf("stdout %q", out)
	}
}

func TestSigningKeyRevoke(t *testing.T) {
	t.Run("certificate with a row", func(t *testing.T) {
		e := newSKEnv(t)
		a, b := e.leaf(), e.leaf()
		n0 := e.trustNumber()
		code, out, errOut := e.sk("revoke", "-cert", certFile(t, a))
		wantExit(t, code, 0, errOut)
		n1 := e.trustNumber()
		if want := fmt.Sprintf("revoked %s human-messages 0\ntrust-number %d\n", tp(a), n1); out != want || n1 <= n0 {
			t.Fatalf("stdout %q, want %q (number %d -> %d)", out, want, n0, n1)
		}
		// Repeated: unchanged, the number does not move.
		code, out, errOut = e.sk("revoke", "-cert", certFile(t, a))
		wantExit(t, code, 0, errOut)
		if want := fmt.Sprintf("unchanged %s\ntrust-number %d\n", pki.SerialText(a.SerialNumber), n1); out != want || e.trustNumber() != n1 {
			t.Fatalf("repeat: %q, want %q", out, want)
		}
		// The other leaf is untouched.
		if _, l, _ := e.sk("list"); !strings.Contains(l, tp(b)+" serial "+pki.SerialText(b.SerialNumber)+" ") || strings.Count(l, " revoked\n") != 1 {
			t.Fatalf("list: %q", l)
		}
	})

	t.Run("serial that list printed", func(t *testing.T) {
		e := newSKEnv(t)
		a := e.leaf()
		n0 := e.trustNumber()
		s := pki.SerialText(a.SerialNumber)
		code, out, errOut := e.sk("revoke", "-serial", s)
		wantExit(t, code, 0, errOut)
		n1 := e.trustNumber()
		if want := fmt.Sprintf("revoked %s human-messages 0\ntrust-number %d\n", tp(a), n1); out != want || n1 <= n0 {
			t.Fatalf("stdout %q, want %q (number %d -> %d)", out, want, n0, n1)
		}
		// Upper case is the same number; the repeat is unchanged.
		code, out, errOut = e.sk("revoke", "-serial", strings.ToUpper(s))
		wantExit(t, code, 0, errOut)
		if want := fmt.Sprintf("unchanged %s\ntrust-number %d\n", s, n1); out != want {
			t.Fatalf("repeat: %q, want %q", out, want)
		}
	})

	t.Run("serial no row has", func(t *testing.T) {
		e := newSKEnv(t)
		n0 := e.trustNumber()
		code, out, errOut := e.sk("revoke", "-serial", "00ABCDEF01")
		wantExit(t, code, 0, errOut)
		n1 := e.trustNumber()
		if want := fmt.Sprintf("revoked abcdef01 human-messages 0\ntrust-number %d\n", n1); out != want || n1 <= n0 {
			t.Fatalf("stdout %q, want %q (number %d -> %d)", out, want, n0, n1)
		}
		code, out, _ = e.sk("revoke", "-serial", "abcdef01")
		if want := fmt.Sprintf("unchanged abcdef01\ntrust-number %d\n", n1); code != 0 || out != want {
			t.Fatalf("repeat: %d %q, want %q", code, out, want)
		}
	})

	t.Run("certificate without a row", func(t *testing.T) {
		e := newSKEnv(t)
		a := e.leaf()
		_, st := e.core()
		err := st.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.TrustCertificates(ctx, store.TrustLeaf)
			if err != nil {
				return err
			}
			ids := make([]int64, len(rows))
			for i, r := range rows {
				ids[i] = r.ID
			}
			_, err = tx.DeleteTrustCertificates(ctx, ids)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		n0 := e.trustNumber()
		code, out, errOut := e.sk("revoke", "-cert", certFile(t, a))
		wantExit(t, code, 0, errOut)
		n1 := e.trustNumber()
		if want := fmt.Sprintf("revoked %s human-messages 0\ntrust-number %d\n", tp(a), n1); out != want || n1 <= n0 {
			t.Fatalf("stdout %q, want %q (number %d -> %d)", out, want, n0, n1)
		}
	})

	t.Run("a certificate another key signed", func(t *testing.T) {
		e := newSKEnv(t)
		other := e.f.Sibling(t, "other-install")
		c, _ := e.core()
		_, foreign := other.Leaf(t, c, time.Now(), 24*time.Hour)
		n0 := e.trustNumber()
		code, out, errOut := e.sk("revoke", "-cert", certFile(t, foreign))
		wantExit(t, code, 2, errOut)
		if out != "" || !strings.Contains(errOut, "not signed by the configured intermediate key") || e.trustNumber() != n0 {
			t.Fatalf("stdout %q stderr %q", out, errOut)
		}
	})

	t.Run("lock held is retryable", func(t *testing.T) {
		e := newSKEnv(t)
		a := e.leaf()
		_, st := e.core()
		now := time.Now().UnixMilli()
		if held, err := st.TryLock(context.Background(), signingkeys.LockName, "another-replica", now, now+time.Hour.Milliseconds()); err != nil || !held {
			t.Fatalf("lock: %v %v", held, err)
		}
		for _, args := range [][]string{{"rotate"}, {"revoke", "-cert", certFile(t, a)}, {"revoke", "-serial", "1f"}} {
			code, out, errOut := e.sk(args...)
			wantExit(t, code, 1, errOut)
			if out != "" || !strings.Contains(errOut, "try again") {
				t.Fatalf("%v: stdout %q stderr %q", args, out, errOut)
			}
		}
	})
}

// Every input the command refuses is exit 2 with a message and writes nothing.
func TestSigningKeyRevokeRefusals(t *testing.T) {
	e := newSKEnv(t)
	a := e.leaf()
	good := certFile(t, a)
	two := writeTemp(t, "two.pem", append(pki.EncodePEM("CERTIFICATE", a.Raw), pki.EncodePEM("CERTIFICATE", a.Raw)...))
	wrongType := writeTemp(t, "req.pem", pki.EncodePEM("CERTIFICATE REQUEST", a.Raw))
	garbage := writeTemp(t, "garbage.pem", pki.EncodePEM("CERTIFICATE", []byte("not a certificate")))
	empty := writeTemp(t, "empty.pem", nil)
	missing := filepath.Join(t.TempDir(), "absent.pem")
	n0 := e.trustNumber()
	for _, tc := range []struct {
		name string
		args []string
		want string // a substring of stderr
	}{
		{"neither", []string{"revoke"}, "exactly one of -cert or -serial"},
		{"both", []string{"revoke", "-cert", good, "-serial", "1f"}, "exactly one of -cert or -serial"},
		{"empty serial", []string{"revoke", "-serial", ""}, "exactly one of -cert or -serial"},
		{"not hexadecimal", []string{"revoke", "-serial", "xyz"}, "hexadecimal"},
		{"0x prefix", []string{"revoke", "-serial", "0x1f"}, "hexadecimal"},
		{"sign", []string{"revoke", "-serial", "-1f"}, "hexadecimal"},
		{"plus sign", []string{"revoke", "-serial", "+1f"}, "hexadecimal"},
		{"underscore", []string{"revoke", "-serial", "1_f"}, "hexadecimal"},
		{"zero", []string{"revoke", "-serial", "000"}, "must be positive"},
		{"too long", []string{"revoke", "-serial", strings.Repeat("ff", 20)}, "longer than 20 octets"},
		{"missing file", []string{"revoke", "-cert", missing}, "absent.pem"},
		{"empty file", []string{"revoke", "-cert", empty}, "empty.pem"},
		{"two blocks", []string{"revoke", "-cert", two}, "two.pem"},
		{"wrong block type", []string{"revoke", "-cert", wrongType}, "req.pem"},
		{"unparseable", []string{"revoke", "-cert", garbage}, "garbage.pem"},
		{"extra argument", []string{"revoke", "-serial", "1f", "extra"}, "unexpected argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := e.sk(tc.args...)
			wantExit(t, code, 2, errOut)
			if out != "" || !strings.Contains(errOut, tc.want) {
				t.Fatalf("stdout %q stderr %q, want %q", out, errOut, tc.want)
			}
		})
	}
	if e.trustNumber() != n0 {
		t.Fatal("a refused revoke changed the trust number")
	}
}

// Without the trust settings every verb is exit 2 naming the missing setting.
func TestSigningKeyRequiresTrust(t *testing.T) {
	e := newAdminEnv(t)
	for _, args := range [][]string{{"list"}, {"rotate"}, {"revoke", "-serial", "1f"}} {
		code, _, errOut := e.run(append([]string{"signing-key"}, args...)...)
		if code != 2 || !strings.Contains(errOut, "root_certificate_file") {
			t.Errorf("%v: code %d stderr %q, want 2 naming root_certificate_file", args, code, errOut)
		}
	}
}

func TestSigningKeyUsage(t *testing.T) {
	e := newAdminEnv(t)
	for _, bad := range [][]string{
		{"signing-key"},
		{"signing-key", "bogus"},
		{"signing-key", "list", "extra"},
		{"signing-key", "list", "-revoke-previous"},
		{"signing-key", "rotate", "-revoke-previous"},
		{"signing-key", "rotate", "-cert", "x"},
		{"signing-key", "rotate", "-from", "x"},
		{"signing-key", "rotate", "extra"},
	} {
		code, _, errOut := e.run(bad...)
		if code != 2 || errOut == "" {
			t.Errorf("%v: code %d stderr %q, want 2 with a message", bad, code, errOut)
		}
	}
	if code, _, errOut := e.run("signing-key"); !strings.Contains(errOut, "list | rotate | revoke -cert FILE | -serial S") {
		t.Errorf("usage text %q (code %d)", errOut, code)
	}
	// A usage error never opens the store: a path that cannot be created is not touched.
	var o, er bytes.Buffer
	if code := RunAdmin(context.Background(), []string{"-sqlite", "/nonexistent-dir/x.db", "signing-key", "revoke"}, nil, &o, &er); code != 2 {
		t.Errorf("usage error with an unopenable store: code %d stderr %q", code, er.String())
	}
}

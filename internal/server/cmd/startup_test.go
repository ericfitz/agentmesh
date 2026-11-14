package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/keyprovider/kmsfake"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/pki/rootca"
	"github.com/ericfitz/agentmesh/internal/server/config"
	"github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/trusttest"
)

// startEnv is one SQLite file with a fixture CA whose intermediate is installed
// (through `ca install`), for tests that start the server over it.
type startEnv struct{ *caEnv }

func newStartEnv(t *testing.T) *startEnv {
	t.Helper()
	e := &startEnv{newCAEnv(t)}
	if code, _, errOut := e.ca("install", e.f.CertFile); code != 0 {
		t.Fatalf("ca install: exit %d: %s", code, errOut)
	}
	return e
}

// args is the start's arguments with the settings in sets ("name=value" each).
func (e *startEnv) args(sets ...string) []string {
	a := []string{"-listen", "127.0.0.1:0", "-sqlite", e.file}
	for _, s := range sets {
		a = append(a, "-set", s)
	}
	return a
}

// trustSets is the fixture's three trust settings.
func (e *startEnv) trustSets() []string {
	return []string{"root_certificate_file=" + e.f.RootFile, "installation_name=" + e.f.Installation, "intermediate_key_file=" + e.f.KeyFile}
}

// without is trustSets minus the settings that start with prefix.
func (e *startEnv) without(prefix string) []string {
	var out []string
	for _, s := range e.trustSets() {
		if !strings.HasPrefix(s, prefix) {
			out = append(out, s)
		}
	}
	return out
}

// start runs the start sequence through run with a serving function that
// returns at once, and returns the exit code and what it printed.
func start(args []string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = run(context.Background(), args, nil, &o, &e, func(context.Context, Config) error { return nil })
	return code, o.String(), e.String()
}

// startWithKeyURI starts the server over a fresh fixture CA (nothing installed)
// with the setting uri ("intermediate_key_uri=..."): the start stops at the
// backend before it reads a key or opens the Store.
func startWithKeyURI(t *testing.T, uri string) (code int, stdout, stderr string) {
	t.Helper()
	f := trusttest.New(t, time.Time{})
	return start([]string{"-listen", "127.0.0.1:0", "-sqlite", filepath.Join(t.TempDir(), "ab2.db"),
		"-set", "root_certificate_file=" + f.RootFile, "-set", "installation_name=" + f.Installation, "-set", uri})
}

// installExternal makes the fixture's intermediate for the key service fake
// holds (a request under its key, signed by the root) and installs it.
func installExternal(t *testing.T, e *startEnv, uri string) {
	t.Helper()
	code, out, errOut := e.caWith("intermediate_key_uri="+uri, "csr")
	wantExit(t, code, 0, errOut)
	csr, err := pki.ParseRequestPEM([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := rootca.Sign(e.f.Dir, csr, 365, true, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	file := writeTemp(t, "ext.pem", pki.EncodePEM("CERTIFICATE", cert.Raw))
	code, _, errOut = e.caWith("intermediate_key_uri="+uri, "install", file)
	wantExit(t, code, 0, errOut)
}

// TestStartupStates is the exit table of ADR 0019 section 4.15 (the start), one
// subtest per row, through run: the exit code and one phrase of the message.
func TestStartupStates(t *testing.T) {
	check := func(t *testing.T, code int, stderr string, wantCode int, phrases ...string) {
		t.Helper()
		if code != wantCode {
			t.Fatalf("exit %d, want %d; stderr %q", code, wantCode, stderr)
		}
		for _, p := range phrases {
			if !strings.Contains(stderr, p) {
				t.Fatalf("stderr %q lacks %q", stderr, p)
			}
		}
		if strings.Contains(stderr, "panic") {
			t.Fatalf("stderr %q", stderr)
		}
	}
	listensNever := func(t *testing.T, stdout string) {
		t.Helper()
		if strings.Contains(stdout, "listening") {
			t.Fatalf("a refused start printed %q", stdout)
		}
	}

	t.Run("root unset", func(t *testing.T) {
		e := newStartEnv(t)
		code, out, errs := start(e.args(e.without("root_certificate_file")...))
		check(t, code, errs, 2, "root_certificate_file")
		listensNever(t, out)
	})
	t.Run("root unreadable", func(t *testing.T) {
		e := newStartEnv(t)
		sets := append(e.without("root_certificate_file"), "root_certificate_file="+filepath.Join(t.TempDir(), "none.pem"))
		code, _, errs := start(e.args(sets...))
		check(t, code, errs, 2, "root_certificate_file")
	})
	t.Run("root not a certificate", func(t *testing.T) {
		e := newStartEnv(t)
		sets := append(e.without("root_certificate_file"), "root_certificate_file="+writeTemp(t, "junk.pem", []byte("not a certificate")))
		code, _, errs := start(e.args(sets...))
		check(t, code, errs, 2, "root_certificate_file")
	})
	t.Run("root not a CA certificate", func(t *testing.T) {
		e := newStartEnv(t)
		// a self-signed certificate that is not a CA
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "not a ca"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		sets := append(e.without("root_certificate_file"), "root_certificate_file="+writeTemp(t, "leaf.pem", pki.EncodePEM("CERTIFICATE", der)))
		code, _, errs := start(e.args(sets...))
		check(t, code, errs, 2, "root_certificate_file")
	})
	t.Run("root with two certificates", func(t *testing.T) {
		e := newStartEnv(t)
		b, err := os.ReadFile(e.f.RootFile)
		if err != nil {
			t.Fatal(err)
		}
		two := writeTemp(t, "two.pem", append(append([]byte{}, b...), b...))
		sets := append(e.without("root_certificate_file"), "root_certificate_file="+two)
		code, _, errs := start(e.args(sets...))
		check(t, code, errs, 2, "root_certificate_file")
	})
	t.Run("pinned root expired", func(t *testing.T) {
		old := time.Now().AddDate(-11, 0, 0)
		f := trusttest.New(t, old)
		e := newStartEnv(t)
		sets := []string{"root_certificate_file=" + f.RootFile, "installation_name=" + e.f.Installation, "intermediate_key_file=" + e.f.KeyFile}
		code, out, errs := start(e.args(sets...))
		check(t, code, errs, 2, "root_certificate_file", "expired")
		listensNever(t, out)
	})
	t.Run("installation name unset", func(t *testing.T) {
		e := newStartEnv(t)
		code, _, errs := start(e.args(e.without("installation_name")...))
		check(t, code, errs, 2, "installation_name")
	})
	t.Run("installation name invalid", func(t *testing.T) {
		e := newStartEnv(t)
		sets := append(e.without("installation_name"), "installation_name=Not A Name!")
		code, _, errs := start(e.args(sets...))
		check(t, code, errs, 2, "installation_name")
	})
	t.Run("neither key setting", func(t *testing.T) {
		e := newStartEnv(t)
		code, _, errs := start(e.args(e.without("intermediate_key_file")...))
		check(t, code, errs, 2, "intermediate_key_file", "intermediate_key_uri")
	})
	t.Run("both key settings", func(t *testing.T) {
		e := newStartEnv(t)
		code, _, errs := start(e.args(append(e.trustSets(), "intermediate_key_uri=awskms://alias/x")...))
		check(t, code, errs, 2, "intermediate_key_file", "intermediate_key_uri")
	})
	t.Run("key file missing", func(t *testing.T) {
		e := newStartEnv(t)
		sets := append(e.without("intermediate_key_file"), "intermediate_key_file="+filepath.Join(t.TempDir(), "none.key"))
		code, _, errs := start(e.args(sets...))
		check(t, code, errs, 2, "none.key")
	})
	t.Run("key file not P-256", func(t *testing.T) {
		e := newStartEnv(t)
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "p384.key")
		if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		sets := append(e.without("intermediate_key_file"), "intermediate_key_file="+file)
		code, _, errs := start(e.args(sets...))
		check(t, code, errs, 2, "p384.key")
	})
	t.Run("no stored intermediate", func(t *testing.T) {
		e := newCAEnv(t) // nothing installed
		se := &startEnv{e}
		code, out, errs := start(se.args(se.trustSets()...))
		check(t, code, errs, 2, "ca csr", "ca install")
		listensNever(t, out)
	})
	t.Run("intermediate expired", func(t *testing.T) {
		e := &startEnv{newCAEnv(t)}
		// An intermediate that expired 35 days ago, installed while it was valid.
		f := trusttest.New(t, time.Now().AddDate(0, 0, -400))
		e.f = f
		c, st := e.core()
		defer func() { _ = st.Close() }()
		past := time.Now().AddDate(0, 0, -399)
		tr := f.Trust(c)
		tr.Core = coreAt(t, st, past)
		if _, err := tr.InstallIntermediate(context.Background(), f.Intermediate); err != nil {
			t.Fatal(err)
		}
		code, _, errs := start(e.args(e.trustSets()...))
		check(t, code, errs, 2, "expired")
	})
	t.Run("intermediate revoked", func(t *testing.T) {
		e := newStartEnv(t)
		if code, _, errOut := e.ca("install-crl", crlFile(t, e.f.RevokeIntermediate(t, time.Now()))); code != 0 {
			t.Fatalf("install-crl: exit %d: %s", code, errOut)
		}
		code, _, errs := start(e.args(e.trustSets()...))
		check(t, code, errs, 2, "revokes")
	})
	t.Run("backend not in this build", func(t *testing.T) {
		setBackend(t, "awskms", nil)
		code, out, errs := startWithKeyURI(t, "intermediate_key_uri=awskms://alias/x")
		check(t, code, errs, 2, "-tags awskms")
		listensNever(t, out)
	})
	t.Run("backend reports its service unreachable", func(t *testing.T) {
		setBackend(t, "awskms", func(string) (keyprovider.Provider, error) {
			return nil, fmt.Errorf("dial: %w", keyprovider.ErrUnavailable)
		})
		e := newStartEnv(t)
		sets := []string{e.trustSets()[0], e.trustSets()[1], "intermediate_key_uri=awskms://alias/x"}
		code, _, errs := start(e.args(sets...))
		check(t, code, errs, 1, "dial")
	})
	t.Run("malformed key URI", func(t *testing.T) {
		setBackend(t, "awskms", func(string) (keyprovider.Provider, error) { return nil, errors.New("bad key URI") })
		e := newStartEnv(t)
		sets := []string{e.trustSets()[0], e.trustSets()[1], "intermediate_key_uri=awskms://alias/x"}
		code, _, errs := start(e.args(sets...))
		check(t, code, errs, 2, "bad key URI")
	})
	t.Run("key service down while the first leaf is issued", func(t *testing.T) {
		fake := kmsfake.New("awskms")
		useFake(t, fake)
		e := newStartEnv(t)
		const uri = "awskms://alias/agentmesh?token=s3cret"
		installExternal(t, e, uri)
		fake.SetDown(true)
		sets := []string{e.trustSets()[0], e.trustSets()[1], "intermediate_key_uri=" + uri}
		code, out, errs := start(e.args(sets...))
		check(t, code, errs, 1, "signing key")
		listensNever(t, out)
		if strings.Contains(errs, "s3cret") || strings.Contains(errs, "awskms://") {
			t.Fatalf("the key URI leaked: %q", errs)
		}
	})
	t.Run("token lifetime above half the leaf validity", func(t *testing.T) {
		e := newStartEnv(t)
		code, _, errs := start(e.args(append(e.trustSets(), "leaf_validity_hours=2", "token_lifetime_seconds=3601")...))
		check(t, code, errs, 2, "token_lifetime_seconds")
	})
	t.Run("human token lifetime above half the leaf validity", func(t *testing.T) {
		e := newStartEnv(t)
		issuers := `[{"name":"idp","issuer":"https://idp.example","jwks_uri":"https://idp.example/jwks","audience":"a","human_token_lifetime_seconds":3601}]`
		code, _, errs := start(e.args(append(e.trustSets(), "leaf_validity_hours=2", "issuers="+issuers)...))
		check(t, code, errs, 2, "human_token_lifetime_seconds")
	})
	t.Run("the store does not answer", func(t *testing.T) {
		e := newStartEnv(t)
		a := []string{"-listen", "127.0.0.1:0", "-sqlite", t.TempDir()} // a directory is not a database
		for _, s := range e.trustSets() {
			a = append(a, "-set", s)
		}
		code, _, errs := start(a)
		check(t, code, errs, 1, "sqlite")
	})
}

// TestStartFailureMapsEveryManagerState pins the exit of each error of
// signingkeys.New, including ErrRootExpired, which the start's own root check
// reaches first with the clock the start reads (so no `run` call can produce it).
func TestStartFailureMapsEveryManagerState(t *testing.T) {
	cfg := config.Config{IntermediateKeyFile: "k"}
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"no intermediate":      {fmt.Errorf("x: %w", signingkeys.ErrNoIntermediate), 2},
		"intermediate expired": {fmt.Errorf("x: %w", signingkeys.ErrIntermediateExpired), 2},
		"intermediate revoked": {fmt.Errorf("x: %w", signingkeys.ErrIntermediateRevoked), 2},
		"root expired":         {fmt.Errorf("x: %w", signingkeys.ErrRootExpired), 2},
		"key service down":     {fmt.Errorf("x: %w", keyprovider.ErrUnavailable), 1},
		"canceled":             {context.Canceled, 1},
		"deadline":             {context.DeadlineExceeded, 1},
		"key file unusable":    {errors.New("key file mismatch"), 2},
	} {
		if got := startExit(startFailure(cfg, tc.err)); got != tc.want {
			t.Errorf("%s: exit %d, want %d", name, got, tc.want)
		}
	}
	if got := startExit(startFailure(config.Config{IntermediateKeyURI: "awskms://k"}, errors.New("sign refused"))); got != 1 {
		t.Errorf("a key service's other failure: exit %d, want 1", got)
	}
}

// TestStartLine: the start line names the leaf thumbprint and its end as an RFC
// 3339 time; the lines of the retired key set are gone.
func TestStartLine(t *testing.T) {
	e := newStartEnv(t)
	r := launch(t, nil, e.args(e.trustSets()...)...).waitReady()
	defer r.stop()
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(r.leaf) {
		t.Errorf("leaf %q is not a base64url SHA-256 thumbprint", r.leaf)
	}
	until, err := time.Parse(time.RFC3339, r.until)
	if err != nil {
		t.Fatalf("until %q: %v", r.until, err)
	}
	if want := time.Now().Add(config.Default().LeafValidity()); until.Before(want.Add(-time.Hour)) || until.After(want.Add(time.Hour)) {
		t.Errorf("until %s, want about %s", until, want)
	}
	if !slicesContains(jwksKIDs(t, r.base()), r.leaf) {
		t.Errorf("the leaf %s is not in the key set", r.leaf)
	}
	for _, old := range []string{"generated signing key", "adopted signing key", ", kid "} {
		if strings.Contains(r.stdout.String(), old) {
			t.Errorf("stdout %q still has %q", r.stdout.String(), old)
		}
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestSecondStartIssuesAnotherLeaf: two starts over one store leave two leaf
// rows, and a bearer of the first start's leaf still verifies on the second.
func TestSecondStartIssuesAnotherLeaf(t *testing.T) {
	e := newStartEnv(t)
	args := e.args(append(e.trustSets(), "issuer=http://agentmesh.local")...)
	first := launch(t, nil, args...).waitReady()
	_, tok := registerAndMint(t, first, "pat")
	if got := first.stop(); got != 0 {
		t.Fatalf("exit %d", got)
	}
	if n := leafRows(t, e.file); n != 1 {
		t.Fatalf("leaf rows after one start = %d, want 1", n)
	}
	second := launch(t, nil, args...).waitReady()
	defer second.stop()
	if n := leafRows(t, e.file); n != 2 {
		t.Fatalf("leaf rows after two starts = %d, want 2", n)
	}
	if second.leaf == first.leaf {
		t.Fatalf("the second start reused the leaf %s", first.leaf)
	}
	if code, body := httpDo(t, nil, "GET", second.base()+"/v1/channels", tok.Token); code != 200 {
		t.Fatalf("the first start's bearer: %d %s", code, body)
	}
}

// TestStartRefusedBeforeTheStoreLeavesNothing: a start that fails the root,
// key file or settings checks opens no Store, so the database file does not
// appear.
func TestStartRefusedBeforeTheStoreLeavesNothing(t *testing.T) {
	f := trusttest.New(t, time.Time{})
	db := filepath.Join(t.TempDir(), "never.db")
	code, _, errs := start([]string{"-listen", "127.0.0.1:0", "-sqlite", db, "-set", "root_certificate_file=" + f.RootFile,
		"-set", "installation_name=" + f.Installation, "-set", "intermediate_key_file=" + filepath.Join(t.TempDir(), "none.key")})
	if code != 2 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if _, err := os.Stat(db); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the database file exists after a refused start: %v", err)
	}
}

// TestStartOnKeyServicePrintsNoURI: with the intermediate key in a key service,
// the start serves and neither stream carries the key URI.
func TestStartOnKeyServicePrintsNoURI(t *testing.T) {
	fake := kmsfake.New("awskms")
	useFake(t, fake)
	e := newStartEnv(t)
	const uri = "awskms://alias/agentmesh?token=s3cret"
	installExternal(t, e, uri)
	sets := []string{e.trustSets()[0], e.trustSets()[1], "intermediate_key_uri=" + uri}
	r := launch(t, nil, e.args(sets...)...).waitReady()
	if out := r.stdout.String() + r.stderr.String(); strings.Contains(out, "s3cret") || strings.Contains(out, "awskms://") {
		t.Fatalf("the key URI leaked: %q", out)
	}
	if r.stop() != 0 {
		t.Fatal("the start did not exit 0")
	}
}

// coreAt is a core over st whose clock is fixed at t.
func coreAt(t *testing.T, st store.Store, at time.Time) *core.Core {
	t.Helper()
	c, err := core.New(st, core.Defaults(), core.Options{Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

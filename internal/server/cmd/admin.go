package cmd

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/identities"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/server/config"
	"github.com/ericfitz/agentmesh/internal/store"
)

const adminSubcommands = "users and admins (add, remove, list), reset-credential, create-identity, create-human, enrollment (create, list, revoke), signing-key (list, rotate, revoke), ca (csr, install, install-crl, status)"

const makeAdminReplaced = "make-admin was replaced by: admins add -identity NAME (admins remove -identity NAME)"

const createIdentityUsage = `usage: agentmesh server admin create-identity NAME [-scope S]

Creates a keyless row for an identity that will register a key later; in open
mode any registrant may bind a key to a keyless name that is not an
administrator, while a keyless administrator can only be claimed with an
enrollment token bound to its name (enrollment create -identity NAME).

With -scope S (an open scope) the identity is a scoped agent: it holds no
general subscription and can be claimed only with the enrollment token this
command prints (bound to NAME, one use, 24 hours). Running it again for a
keyless agent of the same scope prints a fresh token and revokes the earlier
one.
`

// hostEnv is what a host command runs against: the identities service and the
// names of the configured issuers (none: every claim-kind add is refused).
type hostEnv struct {
	Svc     identities.Service
	Issuers []string
	// Config is the merged configuration; the ca commands read the trust settings.
	Config config.Config
	// Trust is the trust rules over the Core for the configured root, name and
	// key; it checks cfg.RequireTrust first. sign false leaves Provider nil.
	Trust func(sign bool) (signingkeys.Trust, error)
}

type adminAction func(context.Context, hostEnv, io.Writer) error

// RunAdmin is `agentmesh server admin`: host commands against the Store with
// no listener and no credential. Exit codes: 0 success or -h, 1 runtime or
// service error, 2 flag, configuration or usage error. listen and registration
// are never consulted. Ported from v1 main.go (run's subcommand dispatch,
// parseExit).
func RunAdmin(ctx context.Context, args []string, environ []string, stdout, stderr io.Writer) int {
	var f flags
	fs := flagSet("agentmesh server admin", &f, false)
	var usage bytes.Buffer
	fs.SetOutput(&usage)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(&usage, "usage: agentmesh server admin [flags] SUBCOMMAND [args]\nsubcommands: %s\n", adminSubcommands)
		fs.PrintDefaults()
	}
	if code, done := parseFlags(fs, args, &usage, stdout, stderr); done {
		return code
	}
	rest := fs.Args()
	if len(rest) == 0 {
		_, _ = fmt.Fprintf(stderr, "agentmesh server admin: a subcommand is required: %s\n", adminSubcommands)
		return 2
	}
	sub, subArgs := rest[0], rest[1:]

	// Parse the subcommand's own arguments before opening the store, so a
	// usage error never touches it.
	var (
		run  adminAction
		code int
		done bool
	)
	switch sub {
	case "make-admin":
		_, _ = fmt.Fprintln(stderr, makeAdminReplaced)
		return 2
	case "users", "admins":
		run, code, done = referenceCommand(sub, subArgs, stdout, stderr)
	case "reset-credential":
		run, code, done = resetCredentialCommand(subArgs, stdout, stderr)
	case "create-identity":
		run, code, done = createIdentityCommand(subArgs, stdout, stderr)
	case "create-human":
		run, code, done = createHumanCommand(subArgs, stdout, stderr)
	case "enrollment":
		run, code, done = enrollmentCommand(subArgs, stdout, stderr)
	case "signing-key":
		run, code, done = signingKeyCommand(subArgs, stdout, stderr)
	case "ca":
		run, code, done = caCommand(subArgs, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "agentmesh server admin: unknown subcommand %q; subcommands: %s\n", sub, adminSubcommands)
		return 2
	}
	if done {
		return code
	}

	cfg, st, cc, err := openFromConfig(ctx, &f, fs, environ, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "agentmesh server admin: %v\n", err)
		var ce *configError
		if errors.As(err, &ce) {
			return 2
		}
		return 1
	}
	defer func() { _ = st.Close() }()
	c, err := core.New(st, cc, core.Options{})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "agentmesh server admin: %v\n", err)
		return 1
	}
	env := hostEnv{
		Config: cfg,
		Trust:  newTrust(c, cfg),
		Svc:    identities.Service{Core: c},
	}
	for _, is := range cfg.Issuers {
		env.Issuers = append(env.Issuers, is.Name)
	}
	if err := run(ctx, env, stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "agentmesh server admin %s: %v\n", sub, err)
		var ce *configError
		if errors.As(err, &ce) {
			return 2
		}
		return 1
	}
	return 0
}

// referenceCommand parses `users|admins add|remove|list`.
func referenceCommand(list string, args []string, stdout, stderr io.Writer) (adminAction, int, bool) {
	use := fmt.Sprintf("usage: agentmesh server admin %s add|remove|list [-issuer NAME] [-email V | -group V | -subject V | -identity NAME]", list)
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, use)
		return nil, 2, true
	}
	action, rest := args[0], args[1:]
	if action != "add" && action != "remove" && action != "list" {
		_, _ = fmt.Fprintf(stderr, "%s: unknown action %q; %s\n", list, action, use)
		return nil, 2, true
	}
	fs, buf := subFlags(list + " " + action)
	var issuer, email, group, subject, identity *string
	if action != "list" {
		issuer = fs.String("issuer", "", "the configured issuer name (claim kinds)")
		email = fs.String("email", "", "match this email address")
		group = fs.String("group", "", "match members of this group")
		subject = fs.String("subject", "", "match this provider subject")
		identity = fs.String("identity", "", "match this identity name")
	}
	pos, code, done := parseInterleaved(fs, buf, rest, stdout, stderr)
	if done {
		return nil, code, true
	}
	if len(pos) != 0 {
		_, _ = fmt.Fprintf(stderr, "%s %s: unexpected argument %q\n", list, action, pos[0])
		return nil, 2, true
	}
	l := store.RefList(list)
	if action == "list" {
		return func(ctx context.Context, e hostEnv, w io.Writer) error {
			refs, err := e.Svc.ListReferences(ctx, l)
			if err != nil {
				return err
			}
			for _, r := range refs {
				_, _ = fmt.Fprintln(w, formatReference(r))
			}
			return nil
		}, 0, false
	}
	r, err := identities.ParseReference(list, *issuer, *email, *group, *subject, *identity)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %s: %v\n", list, action, err)
		return nil, 2, true
	}
	if action == "add" {
		return func(ctx context.Context, e hostEnv, w io.Writer) error {
			added, err := e.Svc.AddReference(ctx, r, e.Issuers)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(w, map[bool]string{true: "added", false: "already present"}[added])
			return nil
		}, 0, false
	}
	return func(ctx context.Context, e hostEnv, w io.Writer) error {
		removed, err := e.Svc.RemoveReference(ctx, r)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(w, map[bool]string{true: "removed", false: "not present"}[removed])
		return nil
	}, 0, false
}

// formatReference is `{issuer: corp, group: pai-users}` or `{identity: pat}`.
func formatReference(r store.Reference) string {
	if r.Kind == store.RefIdentity {
		return fmt.Sprintf("{identity: %s}", r.Value)
	}
	return fmt.Sprintf("{issuer: %s, %s: %s}", r.Issuer, r.Kind, r.Value)
}

func resetCredentialCommand(args []string, stdout, stderr io.Writer) (adminAction, int, bool) {
	fs, buf := subFlags("reset-credential")
	pos, code, done := parseInterleaved(fs, buf, args, stdout, stderr)
	if done {
		return nil, code, true
	}
	if len(pos) != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: agentmesh server admin reset-credential NAME")
		return nil, 2, true
	}
	name := pos[0]
	return func(ctx context.Context, e hostEnv, w io.Writer) error {
		s := e.Svc
		n, err := s.ResetCredential(ctx, name)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(w, "%s: %d credential(s) removed; the name may be registered again\n", name, n)
		return nil
	}, 0, false
}

func createIdentityCommand(args []string, stdout, stderr io.Writer) (adminAction, int, bool) {
	fs, buf := subFlags("create-identity")
	scope := fs.String("scope", "", "create a scoped agent in this open scope and print its bound enrollment token")
	pos, code, done := parseInterleaved(fs, buf, args, stdout, stderr)
	if done {
		return nil, code, true
	}
	if len(pos) != 1 {
		_, _ = io.WriteString(stderr, createIdentityUsage)
		return nil, 2, true
	}
	name := pos[0]
	return func(ctx context.Context, e hostEnv, w io.Writer) error {
		s := e.Svc
		if *scope != "" {
			res, err := s.CreateAgentIdentity(ctx, bus.CreateAgentIdentityInput{Name: name, Scope: *scope})
			if err != nil {
				return err
			}
			verb := "already exists in"
			if res.Created {
				verb = "created in"
			}
			_, _ = fmt.Fprintf(w, "%s %s scope %s\ntoken: %s\nexpires: %s\n", name, verb, *scope, res.EnrollmentToken, time.UnixMilli(res.ExpiresAt).UTC().Format(time.RFC3339))
			return nil
		}
		created, err := s.CreateIdentity(ctx, name)
		if err != nil {
			return err
		}
		if created {
			_, _ = fmt.Fprintf(w, "%s created\n", name)
		} else {
			_, _ = fmt.Fprintf(w, "%s already exists\n", name)
		}
		return nil
	}, 0, false
}

func createHumanCommand(args []string, stdout, stderr io.Writer) (adminAction, int, bool) {
	fs, buf := subFlags("create-human")
	pos, code, done := parseInterleaved(fs, buf, args, stdout, stderr)
	if done {
		return nil, code, true
	}
	if len(pos) != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: agentmesh server admin create-human EMAIL")
		return nil, 2, true
	}
	email := pos[0]
	return func(ctx context.Context, e hostEnv, w io.Writer) error {
		name, created, err := e.Svc.CreateIdentityByEmail(ctx, email)
		if err != nil {
			return err
		}
		if created {
			_, _ = fmt.Fprintf(w, "%s created\n", name)
		} else {
			_, _ = fmt.Fprintf(w, "%s already exists\n", name)
		}
		return nil
	}, 0, false
}

// enrollmentCommand parses `enrollment create|list|revoke`.
func enrollmentCommand(args []string, stdout, stderr io.Writer) (adminAction, int, bool) {
	const use = "usage: agentmesh server admin enrollment create [-identity NAME] [-expires 24h] [-uses 1] | list | revoke ID"
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, use)
		return nil, 2, true
	}
	action, rest := args[0], args[1:]
	switch action {
	case "create":
		fs, buf := subFlags("enrollment create")
		identity := fs.String("identity", "", "bind the token to this name (default: any free name or keyless non-administrator row)")
		expires := fs.Duration("expires", 24*time.Hour, "token lifetime")
		uses := fs.Int("uses", 1, "number of registrations the token allows")
		pos, code, done := parseInterleaved(fs, buf, rest, stdout, stderr)
		if done {
			return nil, code, true
		}
		if len(pos) != 0 {
			_, _ = fmt.Fprintf(stderr, "enrollment create: unexpected argument %q\n", pos[0])
			return nil, 2, true
		}
		if *expires <= 0 || *uses < 1 {
			_, _ = fmt.Fprintln(stderr, "enrollment create: -expires and -uses must be positive")
			return nil, 2, true
		}
		in := identities.TokenInput{Identity: *identity, Expires: *expires, Uses: *uses}
		return func(ctx context.Context, e hostEnv, w io.Writer) error {
			s := e.Svc
			token, row, err := s.CreateEnrollmentToken(ctx, in)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(w, "token: %s\n", token)
			_, _ = fmt.Fprintf(w, "id: %s identity: %s expires: %s uses: %d\n", row.ID, orAny(row.Identity),
				time.UnixMilli(row.ExpiresAt).UTC().Format(time.RFC3339), row.UsesLeft)
			return nil
		}, 0, false
	case "list":
		fs, buf := subFlags("enrollment list")
		pos, code, done := parseInterleaved(fs, buf, rest, stdout, stderr)
		if done {
			return nil, code, true
		}
		if len(pos) != 0 {
			_, _ = fmt.Fprintf(stderr, "enrollment list: unexpected argument %q\n", pos[0])
			return nil, 2, true
		}
		return func(ctx context.Context, e hostEnv, w io.Writer) error {
			s := e.Svc
			rows, err := s.ListEnrollmentTokens(ctx)
			if err != nil {
				return err
			}
			now := s.NowMs()
			for _, r := range rows {
				line := fmt.Sprintf("%s %s %s %d", r.ID, orAny(r.Identity), time.UnixMilli(r.ExpiresAt).UTC().Format(time.RFC3339), r.UsesLeft)
				if r.ExpiresAt <= now {
					line += " expired"
				}
				_, _ = fmt.Fprintln(w, line)
			}
			return nil
		}, 0, false
	case "revoke":
		fs, buf := subFlags("enrollment revoke")
		pos, code, done := parseInterleaved(fs, buf, rest, stdout, stderr)
		if done {
			return nil, code, true
		}
		if len(pos) != 1 {
			_, _ = fmt.Fprintln(stderr, "usage: agentmesh server admin enrollment revoke ID")
			return nil, 2, true
		}
		id := pos[0]
		return func(ctx context.Context, e hostEnv, w io.Writer) error {
			s := e.Svc
			if err := s.RevokeEnrollmentToken(ctx, id); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(w, "%s revoked\n", id)
			return nil
		}, 0, false
	default:
		_, _ = fmt.Fprintf(stderr, "enrollment: unknown action %q; %s\n", action, use)
		return nil, 2, true
	}
}

func orAny(identity string) string {
	if identity == "" {
		return "any"
	}
	return identity
}

func subFlags(name string) (*flag.FlagSet, *bytes.Buffer) {
	fs := flag.NewFlagSet("agentmesh server admin "+name, flag.ContinueOnError)
	buf := &bytes.Buffer{}
	fs.SetOutput(buf)
	return fs, buf
}

// parseFlags parses fs; done reports that the caller should return code.
func parseFlags(fs *flag.FlagSet, args []string, usage *bytes.Buffer, stdout, stderr io.Writer) (code int, done bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stdout, usage)
			return 0, true
		}
		_, _ = io.Copy(stderr, usage)
		return 2, true
	}
	return 0, false
}

// parseInterleaved parses fs allowing flags after positional arguments
// (`create-identity NAME -h`) and returns the positionals.
func parseInterleaved(fs *flag.FlagSet, buf *bytes.Buffer, args []string, stdout, stderr io.Writer) (pos []string, code int, done bool) {
	for {
		if c, d := parseFlags(fs, args, buf, stdout, stderr); d {
			return nil, c, true
		}
		if fs.NArg() == 0 {
			return pos, 0, false
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

const signingKeyUsage = "usage: agentmesh server admin signing-key list | rotate | revoke -cert FILE | -serial S"

// signingKeyCommand parses `signing-key list|rotate|revoke` (ADR 0019 sections
// 4.8 and 4.13): the commands act on leaf certificates under the configured
// intermediate key and print one fact per line.
//
// State (Definition of Done D): rotate lists every unexpired leaf of the
// configured key that no earlier CRL lists, so a second run revokes only the
// leaves issued since and, with none, prints the trust number alone; a repeated
// revoke prints unchanged and writes nothing; two overlapping commands meet the
// trust lock, and the loser exits 1 saying to try again; a run that failed
// before its transaction left the rows as they were.
func signingKeyCommand(args []string, stdout, stderr io.Writer) (adminAction, int, bool) {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, signingKeyUsage)
		return nil, 2, true
	}
	verb, rest := args[0], args[1:]
	if verb != "list" && verb != "rotate" && verb != "revoke" {
		_, _ = fmt.Fprintf(stderr, "signing-key: unknown action %q; %s\n", verb, signingKeyUsage)
		return nil, 2, true
	}
	fs, buf := subFlags("signing-key " + verb)
	var cert, serial *string
	if verb == "revoke" {
		cert = fs.String("cert", "", "the PEM file of one leaf certificate")
		serial = fs.String("serial", "", "one serial number, in hexadecimal as list prints it")
	}
	pos, code, done := parseInterleaved(fs, buf, rest, stdout, stderr)
	if done {
		return nil, code, true
	}
	if len(pos) != 0 {
		_, _ = fmt.Fprintf(stderr, "signing-key %s: unexpected argument %q\n", verb, pos[0])
		return nil, 2, true
	}
	switch verb {
	case "list":
		return signingKeyList, 0, false
	case "rotate":
		return signingKeyRotate(stderr), 0, false
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["cert"] == set["serial"] || (set["serial"] && *serial == "") || (set["cert"] && *cert == "") {
		_, _ = fmt.Fprintf(stderr, "signing-key revoke: exactly one of -cert or -serial is required; %s\n", signingKeyUsage)
		return nil, 2, true
	}
	if set["cert"] {
		return signingKeyRevokeCert(*cert, stderr), 0, false
	}
	n, err := parseSerial(*serial)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "signing-key revoke: %v\n", err)
		return nil, 2, true
	}
	return signingKeyRevoke(signingkeys.RevokeInput{Serial: n}, stderr), 0, false
}

// parseSerial reads a serial number as list prints it: hexadecimal digits only,
// either case. A sign, a "0x" prefix and underscores are refused; zero and an
// over-long number are refused by signingkeys.RevokeInput.
func parseSerial(s string) (*big.Int, error) {
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return nil, fmt.Errorf("-serial %q is not hexadecimal digits (no sign, 0x prefix or separators)", s)
		}
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("-serial %q is not hexadecimal digits", s)
	}
	return n, nil
}

func signingKeyList(ctx context.Context, e hostEnv, w io.Writer) error {
	t, err := e.Trust(false)
	if err != nil {
		return err
	}
	l, err := t.List(ctx, nil)
	if err != nil {
		return trustFailure(e.Config, err)
	}
	for _, k := range l.Keys {
		_, _ = fmt.Fprintf(w, "leaf %s serial %s %s %s %s\n", k.Thumbprint, k.Serial, rfc3339Ms(k.NotBefore), rfc3339Ms(k.NotAfter), k.State)
	}
	_, _ = fmt.Fprintf(w, "trust-number %d\n", l.TrustNumber)
	return nil
}

func signingKeyRotate(stderr io.Writer) adminAction {
	return signingKeyRevoke(signingkeys.RevokeInput{All: true}, stderr)
}

// signingKeyRevokeCert reads the one certificate of file (a missing file or
// any other content than one CERTIFICATE block is exit 2, naming the file).
func signingKeyRevokeCert(file string, stderr io.Writer) adminAction {
	return func(ctx context.Context, e hostEnv, w io.Writer) error {
		b, err := readInput(file)
		if err != nil {
			return err
		}
		c, err := pki.ParseCertificatePEM(b)
		if err != nil {
			return &configError{fmt.Errorf("%s: %w", file, err)}
		}
		return signingKeyRevoke(signingkeys.RevokeInput{Cert: c}, stderr)(ctx, e, w)
	}
}

// signingKeyRevoke runs Trust.Revoke for in and prints what it did: the
// `revoked` lines (with the thumbprint, else the serial number a bare serial
// has), `unchanged S` for a serial number already listed, then the trust
// number; `not-covered` lines go to standard error.
func signingKeyRevoke(in signingkeys.RevokeInput, stderr io.Writer) adminAction {
	return func(ctx context.Context, e hostEnv, w io.Writer) error {
		t, err := e.Trust(true)
		if err != nil {
			return err
		}
		res, err := t.Revoke(ctx, nil, in)
		if err != nil {
			return trustFailure(e.Config, err)
		}
		for _, tp := range res.NotCovered {
			_, _ = fmt.Fprintf(stderr, "not-covered %s\n", tp)
		}
		for _, en := range res.Entries {
			switch {
			case !res.Changed && !in.All:
				_, _ = fmt.Fprintf(w, "unchanged %s\n", en.Serial)
			case en.Thumbprint != "":
				_, _ = fmt.Fprintf(w, "revoked %s human-messages %d\n", en.Thumbprint, en.HumanMessages)
			default:
				_, _ = fmt.Fprintf(w, "revoked %s human-messages %d\n", en.Serial, en.HumanMessages)
			}
		}
		_, _ = fmt.Fprintf(w, "trust-number %d\n", res.TrustNumber)
		return nil
	}
}

func rfc3339Ms(ms int64) string { return time.UnixMilli(ms).UTC().Format(time.RFC3339) }

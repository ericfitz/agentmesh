package cli

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ericfitz/agentmesh/internal/fileacl"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/pki/rootca"
)

const caUsage = "usage: agentmesh ca init -dir DIR [-name NAME] [-days N]\n" +
	"       agentmesh ca sign -dir DIR [-days N] [-same-installation] CSR_FILE\n" +
	"       agentmesh ca revoke -dir DIR CERT_FILE"

// RunCA implements `agentmesh ca init|sign|revoke` (ADR 0019 Decision 9), the
// root tool over internal/pki/rootca. It opens no profile, no server and no
// database. Exit 0 done; 2 usage, a refused input or an unparseable file; 1
// any other failure.
func RunCA(_ context.Context, args []string, _ []string, _ io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return caUsageError(stderr, "")
	}
	switch args[0] {
	case "init":
		return runCAInit(args[1:], stdout, stderr)
	case "sign":
		return runCASign(args[1:], stdout, stderr)
	case "revoke":
		return runCARevoke(args[1:], stdout, stderr)
	}
	return caUsageError(stderr, fmt.Sprintf("unknown subcommand %q", args[0]))
}

func caUsageError(stderr io.Writer, msg string) int {
	if msg != "" {
		_, _ = fmt.Fprintf(stderr, "agentmesh ca: %s\n", msg)
	}
	_, _ = fmt.Fprintln(stderr, caUsage)
	return 2
}

// caFlags parses a subcommand's flags (before the positionals) and returns
// the positionals. ok is false after a usage error was printed.
func caFlags(name string, args []string, stderr io.Writer, setup func(*flag.FlagSet), dir *string, wantArgs int) (rest []string, code int, ok bool) {
	set := flag.NewFlagSet("agentmesh ca "+name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(dir, "dir", "", "the root directory (required)")
	setup(set)
	if err := set.Parse(args); err != nil {
		return nil, caUsageError(stderr, err.Error()), false
	}
	if *dir == "" {
		return nil, caUsageError(stderr, "-dir is required"), false
	}
	if set.NArg() != wantArgs {
		return nil, caUsageError(stderr, fmt.Sprintf("%s takes %d file argument(s), got %d", name, wantArgs, set.NArg())), false
	}
	return set.Args(), 0, true
}

// caFail maps an error to an exit code: a refusal is 2, anything else 1.
func caFail(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "agentmesh ca: %v\n", err)
	if errors.Is(err, rootca.ErrRefused) {
		return 2
	}
	return 1
}

// caRequireRoot refuses a directory that holds no root, before the tool's
// lock is taken (which would otherwise fail on the missing directory).
func caRequireRoot(dir string, stderr io.Writer) (int, bool) {
	if _, err := rootca.Root(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			_, _ = fmt.Fprintf(stderr, "agentmesh ca: %s holds no root (no root.pem; make one with `agentmesh ca init -dir %s`)\n", dir, dir)
			return 2, false
		}
		return caFail(stderr, err), false
	}
	return 0, true
}

// caReadPEM reads a file that must hold one PEM block. A file that is not
// PEM (DER, binary, empty) is refused with that said, ahead of the parser's
// own message about two blocks, trailing text or a wrong type.
func caReadPEM(path string, stderr io.Writer) ([]byte, int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "agentmesh ca: %v\n", err)
		return nil, 2, false
	}
	if block, _ := pem.Decode(b); block == nil {
		_, _ = fmt.Fprintf(stderr, "agentmesh ca: %s holds no PEM block (%d bytes; a DER file must be converted to PEM first)\n", path, len(b))
		return nil, 2, false
	}
	return b, 0, true
}

// caEmit writes a command's result to standard output. A failed write is exit
// 1 with the message on standard error and what is already done (the state the
// root tool committed is not undone: the issued certificate stays in
// state.json and the hint says how to print it again).
func caEmit(stdout, stderr io.Writer, b []byte, hint string) int {
	if _, err := stdout.Write(b); err != nil {
		_, _ = fmt.Fprintf(stderr, "agentmesh ca: writing the result to standard output failed: %v; %s\n", err, hint)
		return 1
	}
	return 0
}

// caRestrict and caCheck are the root key hooks rootca requires (it may not
// import internal/fileacl: ADR 0019, rule pki-leaf). Variables so a test can
// observe them.
var (
	caRestrict = fileacl.OwnerOnly
	caCheck    = checkOwnerOnlyKey
)

// checkOwnerOnlyKey accepts root.key only when no other account can read or
// write it: Unix mode 0600 or narrower, fileacl.CheckOwnerOnly on Windows
// (where a mode means nothing). A symlink is followed and the target checked.
// The message names the fix.
func checkOwnerOnlyKey(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS == "windows" {
		if err := fileacl.CheckOwnerOnly(path); err != nil {
			if errors.Is(err, fileacl.ErrExposed) {
				return fmt.Errorf("%s: %w; restrict it with: %s", path, err, fileacl.WindowsFix(path))
			}
			return fmt.Errorf("check %s: %w", path, err)
		}
		return nil
	}
	if perm := fi.Mode().Perm(); perm&^0o600 != 0 {
		return fmt.Errorf("%s has mode %#o, which other accounts can read or write, and holds the root private key; chmod 600 %s", path, perm, path)
	}
	return nil
}

func runCAInit(args []string, stdout, stderr io.Writer) int {
	var dir, name string
	var days int
	_, code, ok := caFlags("init", args, stderr, func(f *flag.FlagSet) {
		f.StringVar(&name, "name", "agentmesh root", "the root certificate's common name")
		f.IntVar(&days, "days", 0, "the root's lifetime in days (0: the default)")
	}, &dir, 0)
	if !ok {
		return code
	}
	thumb, err := rootca.Init(dir, name, days, time.Now(), caRestrict)
	if err != nil {
		return caFail(stderr, err)
	}
	return caEmit(stdout, stderr, []byte(fmt.Sprintf("root %s\nthumbprint %s\n", filepath.Join(dir, "root.pem"), thumb)),
		"the root exists in "+dir+" (root.pem holds it) but its thumbprint was not printed; it is the SHA-256 of root.pem's certificate")
}

func runCASign(args []string, stdout, stderr io.Writer) int {
	var dir string
	var days int
	var same bool
	rest, code, ok := caFlags("sign", args, stderr, func(f *flag.FlagSet) {
		f.IntVar(&days, "days", 0, "the intermediate's lifetime in days (0: the default)")
		f.BoolVar(&same, "same-installation", false, "accept a new key for a name already recorded with another")
	}, &dir, 1)
	if !ok {
		return code
	}
	if code, ok := caRequireRoot(dir, stderr); !ok {
		return code
	}
	b, code, ok := caReadPEM(rest[0], stderr)
	if !ok {
		return code
	}
	csr, err := pki.ParseRequestPEM(b)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "agentmesh ca: %s: %v\n", rest[0], err)
		return 2
	}
	cert, err := rootca.Sign(dir, csr, days, same, time.Now(), caCheck)
	if err != nil {
		return caFail(stderr, err)
	}
	if code := caEmit(stdout, stderr, pki.EncodePEM("CERTIFICATE", cert.Raw),
		"the certificate is recorded in "+filepath.Join(dir, "state.json")+" (thumbprint "+pki.Thumbprint(cert.Raw)+") but was not printed; "+
			"run the same command again to print a new certificate for the same key (the recorded one stays valid; revoke it with ca revoke if it must not be used)"); code != 0 {
		return code
	}
	_, _ = fmt.Fprintf(stderr, "installation %s\n", cert.Subject.CommonName)
	return 0
}

func runCARevoke(args []string, stdout, stderr io.Writer) int {
	var dir string
	rest, code, ok := caFlags("revoke", args, stderr, func(*flag.FlagSet) {}, &dir, 1)
	if !ok {
		return code
	}
	if code, ok := caRequireRoot(dir, stderr); !ok {
		return code
	}
	b, code, ok := caReadPEM(rest[0], stderr)
	if !ok {
		return code
	}
	cert, err := pki.ParseCertificatePEM(b)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "agentmesh ca: %s: %v\n", rest[0], err)
		return 2
	}
	crl, revoked, err := rootca.Revoke(dir, cert, time.Now(), caCheck)
	if err != nil {
		return caFail(stderr, err)
	}
	for _, t := range revoked {
		_, _ = fmt.Fprintf(stderr, "revoked %s\n", t)
	}
	return caEmit(stdout, stderr, pki.EncodePEM("X509 CRL", crl),
		"the revocation is recorded and the CRL is in "+filepath.Join(dir, "root.crl")+" but was not printed; run the same command again to print the current CRL")
}

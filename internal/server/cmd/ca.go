package cmd

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"time"

	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

const caUsage = "usage: agentmesh server admin ca csr [-out FILE] | install CERT_FILE | install-crl CRL_FILE | status"

// caCommand parses `ca csr|install|install-crl|status` (ADR 0019 section 4.4).
//
// State (Definition of Done D): csr creates the key file once (an existing
// file is never replaced, so a second run prints a CSR for the same key) and
// writes nothing to the database; install and install-crl are idempotent (a
// second run prints unchanged); two overlapping installs meet the trust lock,
// and the loser exits 1 saying to retry; a run that failed leaves the rows as
// they were (each install is one transaction).
func caCommand(args []string, stdout, stderr io.Writer) (adminAction, int, bool) {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, caUsage)
		return nil, 2, true
	}
	verb, rest := args[0], args[1:]
	fs, buf := subFlags("ca " + verb)
	var out *string
	switch verb {
	case "csr":
		out = fs.String("out", "", "write the request to FILE instead of standard output")
	case "install", "install-crl", "status":
	default:
		_, _ = fmt.Fprintf(stderr, "ca: unknown action %q; %s\n", verb, caUsage)
		return nil, 2, true
	}
	pos, code, done := parseInterleaved(fs, buf, rest, stdout, stderr)
	if done {
		return nil, code, true
	}
	want := 0
	if verb == "install" || verb == "install-crl" {
		want = 1
	}
	if len(pos) != want {
		_, _ = fmt.Fprintf(stderr, "ca %s: %d argument(s) given, want %d; %s\n", verb, len(pos), want, caUsage)
		return nil, 2, true
	}
	switch verb {
	case "csr":
		return caCSR(*out), 0, false
	case "install":
		return caInstall(pos[0]), 0, false
	case "install-crl":
		return caInstallCRL(pos[0]), 0, false
	}
	return caStatus, 0, false
}

func caCSR(outFile string) adminAction {
	return func(ctx context.Context, e hostEnv, w io.Writer) error {
		t, err := e.Trust(true)
		if err != nil {
			return err
		}
		if path := e.Config.IntermediateKeyFile; path != "" {
			if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
				if err := keyprovider.CreateKeyFile(path, ownerOnlyRestrict); err != nil && !errors.Is(err, fs.ErrExist) {
					return &configError{fmt.Errorf("create %s: %w", path, err)}
				}
			}
		}
		kctx, cancel := context.WithTimeout(ctx, signingkeys.SignTimeout)
		defer cancel()
		key, err := t.Provider.Next(kctx)
		if err != nil {
			return trustFailure(e.Config, err)
		}
		sg, err := t.Provider.Signer(kctx, key)
		if err != nil {
			return trustFailure(e.Config, err)
		}
		der, err := pki.NewRequest(signingkeys.CryptoSigner(kctx, sg), e.Config.InstallationName)
		if err != nil {
			return trustFailure(e.Config, err)
		}
		pemBytes := pki.EncodePEM("CERTIFICATE REQUEST", der)
		if outFile != "" {
			if err := os.WriteFile(outFile, pemBytes, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", outFile, err)
			}
			return nil
		}
		_, err = w.Write(pemBytes)
		return err
	}
}

func readInput(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, &configError{err}
	}
	return b, nil
}

func caInstall(file string) adminAction {
	return func(ctx context.Context, e hostEnv, w io.Writer) error {
		t, err := e.Trust(true)
		if err != nil {
			return err
		}
		b, err := readInput(file)
		if err != nil {
			return err
		}
		cert, err := pki.ParseCertificatePEM(b)
		if err != nil {
			return &configError{fmt.Errorf("%s: %w", file, err)}
		}
		changed, err := t.InstallIntermediate(ctx, cert)
		if err != nil {
			return trustFailure(e.Config, err)
		}
		thumb := pki.Thumbprint(cert.Raw)
		if !changed {
			_, _ = fmt.Fprintf(w, "unchanged %s\n", thumb)
			return nil
		}
		_, _ = fmt.Fprintf(w, "installed %s installation %s until %s\n", thumb, t.Installation, cert.NotAfter.UTC().Format(time.RFC3339))
		return nil
	}
}

func caInstallCRL(file string) adminAction {
	return func(ctx context.Context, e hostEnv, w io.Writer) error {
		t, err := e.Trust(false)
		if err != nil {
			return err
		}
		b, err := readInput(file)
		if err != nil {
			return err
		}
		crl, err := pki.ParseCRLPEM(b)
		if err != nil {
			return &configError{fmt.Errorf("%s: %w", file, err)}
		}
		changed, err := t.InstallRootCRL(ctx, crl)
		if err != nil {
			return trustFailure(e.Config, err)
		}
		word := "unchanged"
		if changed {
			word = "installed"
		}
		_, _ = fmt.Fprintf(w, "%s root-crl %d\n", word, pki.CRLNumber(crl))
		return nil
	}
}

func caStatus(ctx context.Context, e hostEnv, w io.Writer) error {
	t, err := e.Trust(true)
	if err != nil {
		return err
	}
	m, err := t.Load(ctx, nil)
	if err != nil {
		return trustFailure(e.Config, err)
	}
	_, _ = fmt.Fprintf(w, "root %s until %s\n", pki.Thumbprint(t.Root.Raw), t.Root.NotAfter.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(w, "installation %s\n", t.Installation)
	listed := map[string]bool{}
	for _, c := range m.Intermediates {
		listed[pki.Thumbprint(c.Raw)] = true
		configured, err := t.Configured(ctx, c, m.KeyRefs[pki.Thumbprint(c.Raw)])
		if err != nil {
			return trustFailure(e.Config, err)
		}
		key := "other"
		if configured {
			key = "configured"
		}
		revoked := "no"
		if m.RevokedKeys[pki.KeyID(c.SubjectKeyId)] {
			revoked = "yes"
		}
		_, _ = fmt.Fprintf(w, "intermediate %s %s %s key=%s revoked=%s\n", pki.Thumbprint(c.Raw),
			c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), key, revoked)
	}
	if err := printIgnored(ctx, t, listed, w); err != nil {
		return trustFailure(e.Config, err)
	}
	if m.RootCRL != nil {
		_, _ = fmt.Fprintf(w, "root-crl %d\n", pki.CRLNumber(m.RootCRL))
	} else {
		_, _ = fmt.Fprintln(w, "root-crl none")
	}
	issuers := make([]string, 0, len(m.LeafCRLs))
	for k := range m.LeafCRLs {
		issuers = append(issuers, k)
	}
	sort.Strings(issuers)
	for _, k := range issuers {
		_, _ = fmt.Fprintf(w, "leaf-crl %s %d\n", k, pki.CRLNumber(m.LeafCRLs[k]))
	}
	_, _ = fmt.Fprintf(w, "trust-number %d\n", m.Number)
	now := t.Now()
	for _, l := range m.Leaves {
		if now.After(l.Verified.Leaf.NotAfter) {
			continue
		}
		_, _ = fmt.Fprintf(w, "leaf %s serial %s until %s\n", pki.Thumbprint(l.Verified.Leaf.Raw),
			l.Verified.Leaf.SerialNumber.Text(16), l.Verified.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// printIgnored names every stored intermediate row Load dropped, with the
// reason, so a changed installation_name or root is visible (spec section 4.4).
// It reads the rows itself: the admin Core's log is discarded.
func printIgnored(ctx context.Context, t signingkeys.Trust, listed map[string]bool, w io.Writer) error {
	var rows []store.TrustCertificate
	err := t.Store.Read(ctx, func(ctx context.Context, tx store.Tx) error {
		var err error
		rows, err = tx.TrustCertificates(ctx, store.TrustIntermediate)
		return err
	})
	if err != nil {
		return core.FromStore(err)
	}
	for _, r := range rows {
		if listed[r.Thumbprint] {
			continue
		}
		var reason error
		cert, perr := x509.ParseCertificate(r.DER)
		switch {
		case pki.Thumbprint(r.DER) != r.Thumbprint:
			reason = errors.New("the thumbprint column is not the thumbprint of the DER")
		case perr != nil:
			reason = fmt.Errorf("parse certificate: %w", perr)
		default:
			reason = pki.CheckIntermediate(cert, t.Root, t.Installation)
		}
		if reason == nil {
			reason = errors.New("not verified")
		}
		_, _ = fmt.Fprintf(w, "ignored intermediate %s: %v\n", r.Thumbprint, reason)
	}
	return nil
}

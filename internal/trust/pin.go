package trust

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ericfitz/agentmesh/internal/pki"
)

// Expect is what the profile says: its server URL and the optional expected
// root and installation.
type Expect struct{ Server, RootThumbprint, Installation string }

// Pin is the pinned root with the installation name and the server it came
// from.
type Pin struct {
	Root                             *x509.Certificate
	Thumbprint, Installation, Server string
}

// MismatchError is every "stop, pin nothing, replace nothing" case. What is one
// of "root", "installation", "server", "expected root", "expected
// installation". Held is what the client holds or expects; Got is what it was
// given.
type MismatchError struct{ What, Held, Got string }

func (e *MismatchError) Error() string {
	switch e.What {
	case "root", "installation":
		return fmt.Sprintf("trust: the server's %s is %s, the pinned %s is %s; nothing was changed (to trust the new one, run register or login with -accept-new-root; agentmesh-mcponly: register or check)", e.What, e.Got, e.What, e.Held)
	case "expected root", "expected installation":
		return fmt.Sprintf("trust: the profile expects %s %s, got %s; nothing was pinned", strings.TrimPrefix(e.What, "expected "), e.Held, e.Got)
	default:
		return fmt.Sprintf("trust: the pinned %s is %s, the profile's is %s; nothing was changed (to trust the profile's server, run register or login with -accept-new-root; agentmesh-mcponly: register or check)", e.What, e.Held, e.Got)
	}
}

// Accepted says what Accept did.
type Accepted struct {
	First, Replaced bool
	Old, New        Pin
}

// incompleteError is a pin whose two files disagree or of which only one is
// there: a first contact or a replacement was killed between them. The store
// fails closed; only -accept-new-root (or deleting the directory) recovers.
type incompleteError struct{ dir, why string }

func (e *incompleteError) Error() string {
	return fmt.Sprintf("trust: the pin in %s is incomplete (%s), perhaps after an interrupted run; nothing was changed (run register or login with -accept-new-root, agentmesh-mcponly: register or check, or delete the directory)", e.dir, e.why)
}

// pin reads the pin under the caller's lock. There is no pin only when
// state.json and root.pem are both absent; a pin is both, agreeing on the
// root's thumbprint. Anything between is an *incompleteError (fail closed).
func (s Store) pin() (Pin, bool, error) {
	st, err := s.loadState()
	if err != nil {
		return Pin{}, false, err
	}
	b, err := s.readFile(rootFile)
	if err != nil {
		return Pin{}, false, err
	}
	switch {
	case st == nil && b == nil:
		return Pin{}, false, nil
	case st == nil:
		return Pin{}, false, &incompleteError{s.Dir, "root.pem without state.json"}
	case b == nil:
		return Pin{}, false, &incompleteError{s.Dir, "state.json without root.pem"}
	}
	root, err := pki.ParseCertificatePEM(b)
	if err != nil {
		return Pin{}, false, fmt.Errorf("trust: %s: %w", s.path(rootFile), err)
	}
	if pki.Thumbprint(root.Raw) != st.RootThumb {
		return Pin{}, false, &incompleteError{s.Dir, "root.pem is not the root state.json names"}
	}
	return Pin{Root: root, Thumbprint: pki.Thumbprint(root.Raw), Installation: st.Installation, Server: st.Server}, true, nil
}

// Pinned is the held pin; ok is false when there is none.
func (s Store) Pinned() (p Pin, ok bool, err error) {
	err = s.read(func() (e error) { p, ok, e = s.pin(); return })
	return p, ok, err
}

// checkHeld compares a held pin with e.
func checkHeld(p Pin, e Expect) error {
	if p.Server != e.Server {
		return &MismatchError{What: "server", Held: p.Server, Got: e.Server}
	}
	if e.RootThumbprint != "" && p.Thumbprint != e.RootThumbprint {
		return &MismatchError{What: "expected root", Held: e.RootThumbprint, Got: p.Thumbprint}
	}
	if e.Installation != "" && p.Installation != e.Installation {
		return &MismatchError{What: "expected installation", Held: e.Installation, Got: p.Installation}
	}
	return nil
}

// Check compares a held pin with e: the server URL, then RootThumbprint and
// Installation when set. With no pin there is nothing to compare.
func (s Store) Check(e Expect) error {
	p, ok, err := s.Pinned()
	if err != nil || !ok {
		return err
	}
	return checkHeld(p, e)
}

// Accept takes the root and the name of a discover bundle. No pin: both must
// satisfy e, then they are pinned (First). The same pin: nothing. A different
// root, name or server URL: *MismatchError, unless acceptNew, which checks e
// and then replaces the pin and removes the stored chain, CRLs and kept
// revocations.
func (s Store) Accept(b Bundle, e Expect, acceptNew bool) (Accepted, error) {
	root, err := x509.ParseCertificate(b.Root)
	if err != nil {
		return Accepted{}, fmt.Errorf("trust: the discover answer's root certificate: %w", err)
	}
	if err := pki.CheckRoot(root); err != nil {
		return Accepted{}, fmt.Errorf("trust: the discover answer's root certificate: %w", err)
	}
	if err := pki.ValidInstallationName(b.Installation); err != nil {
		return Accepted{}, fmt.Errorf("trust: the discover answer's installation name: %w", err)
	}
	got := Pin{Root: root, Thumbprint: pki.Thumbprint(root.Raw), Installation: b.Installation, Server: e.Server}
	if e.RootThumbprint != "" && got.Thumbprint != e.RootThumbprint {
		return Accepted{}, &MismatchError{What: "expected root", Held: e.RootThumbprint, Got: got.Thumbprint}
	}
	if e.Installation != "" && b.Installation != e.Installation {
		return Accepted{}, &MismatchError{What: "expected installation", Held: e.Installation, Got: b.Installation}
	}
	var out Accepted
	err = s.withLock(true, func() error {
		held, ok, err := s.pin()
		var inc *incompleteError
		if errors.As(err, &inc) {
			if !acceptNew {
				return err
			}
			err = nil // -accept-new-root completes an incomplete pin
		}
		if err != nil {
			return err
		}
		if ok {
			switch {
			case held.Thumbprint != got.Thumbprint && !acceptNew:
				return &MismatchError{What: "root", Held: held.Thumbprint, Got: got.Thumbprint}
			case held.Installation != got.Installation && !acceptNew:
				return &MismatchError{What: "installation", Held: held.Installation, Got: got.Installation}
			case held.Thumbprint == got.Thumbprint && held.Installation == got.Installation && held.Server == got.Server:
				out = Accepted{Old: held, New: held}
				return nil
			case held.Thumbprint == got.Thumbprint && held.Installation == got.Installation && !acceptNew:
				// Section 4.10: another server URL is the root-mismatch error,
				// which -accept-new-root clears.
				return &MismatchError{What: "server", Held: held.Server, Got: got.Server}
			}
		}
		// Leftovers of a pin that is gone (or incomplete) never meet a new one.
		if !ok {
			if err := s.discardDerived(); err != nil {
				return err
			}
		}
		if err := s.writePin(got); err != nil {
			return err
		}
		// A replacement removes what belonged to the old pin only after the
		// new one is in place; readers ignore what does not fit the pin in
		// the meantime.
		if err := s.discardDerived(); err != nil {
			return err
		}
		out = Accepted{First: !ok, Replaced: ok, New: got}
		if ok {
			out.Old = held
		}
		return nil
	})
	if err != nil {
		return Accepted{}, err
	}
	return out, nil
}

// writePin writes state.json, then root.pem. The old pin is never removed
// first: a kill between the renames leaves an incomplete pin, which every
// reader reports and only -accept-new-root completes.
func (s Store) writePin(p Pin) error {
	if err := s.saveState(&state{Installation: p.Installation, Server: p.Server, RootThumb: p.Thumbprint}); err != nil {
		return err
	}
	return s.writeFile(rootFile, pki.EncodePEM("CERTIFICATE", p.Root.Raw))
}

// discardDerived removes everything applied for a pin (the chain, the CRLs and
// the kept revocations), never the pin.
func (s Store) discardDerived() error {
	for _, n := range []string{intermediatesFile, rootCRLFile, revokedFile} {
		if err := s.remove(n); err != nil {
			return err
		}
	}
	leaves, err := filepath.Glob(filepath.Join(s.Dir, leafCRLPrefix+"*"+crlSuffix))
	if err != nil {
		return err
	}
	for _, p := range leaves {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("trust: remove %s: %w", p, err)
		}
	}
	return nil
}

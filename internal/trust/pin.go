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
		return fmt.Sprintf("trust: the server's %s is %s, the pinned %s is %s; nothing was changed (to trust the new one, run register or login with -accept-new-root)", e.What, e.Got, e.What, e.Held)
	case "expected root", "expected installation":
		return fmt.Sprintf("trust: the profile expects %s %s, got %s; nothing was pinned", strings.TrimPrefix(e.What, "expected "), e.Held, e.Got)
	default:
		return fmt.Sprintf("trust: the pinned %s is %s, the profile's is %s", e.What, e.Held, e.Got)
	}
}

// Accepted says what Accept did.
type Accepted struct {
	First, Replaced bool
	Old, New        Pin
}

// pin reads the pin under the caller's lock. A pin is root.pem together with
// state.json; one without the other (a replacement or a first contact that was
// killed between them) is no pin.
func (s Store) pin() (Pin, bool, error) {
	st, err := s.loadState()
	if err != nil || st == nil {
		return Pin{}, false, err
	}
	b, err := s.readFile(rootFile)
	if err != nil || b == nil {
		return Pin{}, false, err
	}
	root, err := pki.ParseCertificatePEM(b)
	if err != nil {
		return Pin{}, false, fmt.Errorf("trust: %s: %w", s.path(rootFile), err)
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
// root or name: *MismatchError, unless acceptNew, which checks e and then
// replaces the pin and removes the stored chain, CRLs and kept revocations.
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
		if err != nil {
			return err
		}
		if ok {
			switch {
			case held.Thumbprint != got.Thumbprint && !acceptNew:
				return &MismatchError{What: "root", Held: held.Thumbprint, Got: got.Thumbprint}
			case held.Installation != got.Installation && !acceptNew:
				return &MismatchError{What: "installation", Held: held.Installation, Got: got.Installation}
			case held.Thumbprint == got.Thumbprint && held.Installation == got.Installation:
				out = Accepted{Old: held, New: held}
				return nil
			}
		}
		if ok {
			if err := s.discard(); err != nil {
				return err
			}
		}
		if err := s.writePin(got); err != nil {
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

// writePin writes state.json, then root.pem: the pin appears when the second
// rename lands, and a kill between them leaves no pin (the next first contact
// overwrites both).
func (s Store) writePin(p Pin) error {
	if err := s.saveState(&state{Installation: p.Installation, Server: p.Server}); err != nil {
		return err
	}
	return s.writeFile(rootFile, pki.EncodePEM("CERTIFICATE", p.Root.Raw))
}

// discard removes the pin and everything applied for it, the pin first.
func (s Store) discard() error {
	for _, n := range []string{stateFile, rootFile, intermediatesFile, rootCRLFile, revokedFile} {
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

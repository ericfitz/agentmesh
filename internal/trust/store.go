// Package trust is the client's per-profile trust store (ADR 0019, spec
// sections 4.9 and 4.10): the pinned root with its installation name, the
// intermediates kept for it, the CRLs and the kept revocations. It imports the
// standard library, internal/filelock and internal/pki only.
//
// Files under <config dir>/trust/<profile> (Plan ruling 20): root.pem and
// state.json together are the pin; intermediates.pem, root.crl,
// leaf-<issuer key>.crl and revoked.json hold what was applied; .lock
// serializes every read and every write across processes. Every write is a
// temporary file in the directory and os.Rename. The directory is 0700 and the
// files 0600.
package trust

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ericfitz/agentmesh/internal/filelock"
	"github.com/ericfitz/agentmesh/internal/pki"
)

const (
	rootFile          = "root.pem"
	stateFile         = "state.json"
	intermediatesFile = "intermediates.pem"
	rootCRLFile       = "root.crl"
	revokedFile       = "revoked.json"
	lockFile          = ".lock"
	leafCRLPrefix     = "leaf-"
	crlSuffix         = ".crl"
	stateVersion      = 1
	crlPEMType        = "X509 CRL"
)

// Dir is the trust directory of a profile.
func Dir(configDir, profile string) string {
	return filepath.Join(configDir, "trust", profile)
}

// Store is one profile's trust directory. The zero value of every other field
// is ready to use; nothing is cached, so every call reads the files.
type Store struct{ Dir string }

// Bundle is a trust bundle as received (section 4.9); every certificate and
// CRL is DER.
type Bundle struct {
	TrustNumber   int64
	Intermediates [][]byte
	RootCRL       []byte
	LeafCRLs      [][]byte
	Root          []byte // discover only
	Installation  string // discover only
}

// state is state.json: the pin's identity beside root.pem, and the held trust
// number (absent until a bundle has been applied).
type state struct {
	Version      int    `json:"version"`
	Installation string `json:"installation"`
	Server       string `json:"server"`
	RootThumb    string `json:"root_thumbprint"`
	TrustNumber  *int64 `json:"trust_number,omitempty"`
}

// errNoDir means the trust directory does not exist (or is not a directory):
// there is nothing held, and a reader creates nothing.
var errNoDir = errors.New("trust: no trust directory")

// withLock runs fn holding the exclusive lock on <dir>/.lock. With create, the
// directory is made first and a failure names it; without, a missing directory
// is errNoDir. A reader that cannot open the lock file for writing (a
// read-only file system) falls back to opening it read-only.
func (s Store) withLock(create bool, fn func() error) (err error) {
	if create {
		if err := os.MkdirAll(s.Dir, 0o700); err != nil {
			return fmt.Errorf("trust: cannot create the trust directory %s: %w", s.Dir, err)
		}
	}
	fi, serr := os.Stat(s.Dir)
	if serr != nil {
		var pe *fs.PathError
		if errors.Is(serr, fs.ErrNotExist) || (errors.As(serr, &pe) && isNotDir(pe.Err)) {
			return errNoDir
		}
		return fmt.Errorf("trust: cannot read the trust directory %s: %w", s.Dir, serr)
	}
	if !fi.IsDir() {
		if create {
			return fmt.Errorf("trust: %s is not a directory", s.Dir)
		}
		return errNoDir
	}
	path := filepath.Join(s.Dir, lockFile)
	f, oerr := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if oerr != nil {
		if create {
			return fmt.Errorf("trust: cannot lock the trust directory %s: %w", s.Dir, oerr)
		}
		var rerr error
		if f, rerr = os.Open(path); rerr != nil {
			return fmt.Errorf("trust: cannot lock the trust directory %s: %w", s.Dir, oerr)
		}
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("trust: close the lock of %s: %w", s.Dir, cerr)
		}
	}()
	if err := filelock.Lock(f); err != nil {
		return fmt.Errorf("trust: lock the trust directory %s: %w", s.Dir, err)
	}
	return fn()
}

// read runs fn under the lock; a missing directory is not an error and fn does
// not run.
func (s Store) read(fn func() error) error {
	if err := s.withLock(false, fn); err != nil && !errors.Is(err, errNoDir) {
		return err
	}
	return nil
}

func (s Store) path(name string) string { return filepath.Join(s.Dir, name) }

// readFile returns a file's bytes, or nil when it does not exist.
func (s Store) readFile(name string) ([]byte, error) {
	b, err := os.ReadFile(s.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", s.path(name), err)
	}
	return b, nil
}

// writeFile replaces a file through a temporary file in the directory and
// os.Rename (a Windows rename can fail for a moment when something else has the
// target open, so it is retried a few times).
func (s Store) writeFile(name string, data []byte) (err error) {
	f, err := os.CreateTemp(s.Dir, name+".tmp*")
	if err != nil {
		return fmt.Errorf("trust: write %s: %w", s.path(name), err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	for i := 0; err == nil; i++ {
		if err = os.Rename(tmp, s.path(name)); err != nil && i < 5 {
			time.Sleep(time.Duration(i+1) * 10 * time.Millisecond)
			err = nil
			continue
		}
		break
	}
	if err != nil {
		return fmt.Errorf("trust: write %s: %w", s.path(name), err)
	}
	return nil
}

// writeIfChanged writes only when the file's bytes differ.
func (s Store) writeIfChanged(name string, data []byte) error {
	held, err := s.readFile(name)
	if err != nil {
		return err
	}
	if held != nil && string(held) == string(data) {
		return nil
	}
	return s.writeFile(name, data)
}

func (s Store) remove(name string) error {
	if err := os.Remove(s.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("trust: remove %s: %w", s.path(name), err)
	}
	return nil
}

func (s Store) loadState() (*state, error) {
	b, err := s.readFile(stateFile)
	if err != nil || b == nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", s.path(stateFile), err)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("trust: %s has version %d, want %d", s.path(stateFile), st.Version, stateVersion)
	}
	return &st, nil
}

func (s Store) saveState(st *state) error {
	st.Version = stateVersion
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(stateFile, append(b, '\n'))
}

func parseCertsPEM(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out, nil
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}

func encodeCertsPEM(cs []*x509.Certificate) []byte {
	var out []byte
	for _, c := range cs {
		out = append(out, pki.EncodePEM("CERTIFICATE", c.Raw)...)
	}
	return out
}

// heldCRLNumber is the number of a stored CRL file that issuer signed; ok is
// false when there is none, it does not parse or it is not issuer's (a
// leftover of another root is never adopted).
func (s Store) heldCRLNumber(name string, issuer *x509.Certificate) (n int64, ok bool, err error) {
	b, err := s.readFile(name)
	if err != nil || b == nil || issuer == nil {
		return 0, false, err
	}
	crl, perr := pki.ParseCRLPEM(b)
	if perr != nil || pki.CheckCRL(crl, issuer) != nil {
		return 0, false, nil
	}
	return pki.CRLNumber(crl), true, nil
}

// heldLeafCRLNumber is the number of the stored leaf CRL of issuer key `key`,
// checked against every kept certificate of that key: after a renewal the file
// was signed under an earlier certificate (same key, another validity period),
// and the number rule is per issuer key (spec 4.10 step 4).
func (s Store) heldLeafCRLNumber(key string, kept []*x509.Certificate) (n int64, ok bool, err error) {
	for _, c := range kept {
		if pki.KeyID(c.SubjectKeyId) != key {
			continue
		}
		n, ok, err = s.heldCRLNumber(leafCRLName(key), c)
		if err != nil || ok {
			return n, ok, err
		}
	}
	return 0, false, nil
}

func leafCRLName(issuerKey string) string { return leafCRLPrefix + issuerKey + crlSuffix }

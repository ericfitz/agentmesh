package keyprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
)

// NameFile is the file provider's name.
const NameFile = "file"

// FileProvider holds the intermediate key in a PKCS#8 PEM file (ADR 0019
// Decision 10). Read returns the file's bytes after the caller's owner-only
// check (Plan ruling 11); a nil Read is an error on use.
type FileProvider struct {
	Path string
	Read func(path string) ([]byte, error)
}

// Name implements Provider.
func (FileProvider) Name() string { return NameFile }

// Next reads the file and returns its key; Ref is empty.
func (p FileProvider) Next(ctx context.Context) (Key, error) {
	if err := ctx.Err(); err != nil {
		return Key{}, err
	}
	_, k, err := p.load()
	return k, err
}

// Signer reads the file again and refuses a key that is not k.KID.
func (p FileProvider) Signer(ctx context.Context, k Key) (Signer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sg, cur, err := p.load()
	if err != nil {
		return nil, err
	}
	if cur.KID != k.KID {
		return nil, fmt.Errorf("keyprovider: %s holds key %q, not %q", p.Path, cur.KID, k.KID)
	}
	return fileSigner{sg}, nil
}

// fileSigner signs with the key of the file, checking the context first.
type fileSigner struct{ s crypto.Signer }

func (s fileSigner) Public() crypto.PublicKey { return s.s.Public() }

func (s fileSigner) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.s.Sign(rand.Reader, digest, opts)
}

func (p FileProvider) load() (crypto.Signer, Key, error) {
	if p.Read == nil {
		return nil, Key{}, fmt.Errorf("keyprovider: %s: no owner-only reader is set", p.Path)
	}
	b, err := p.Read(p.Path)
	if err != nil {
		return nil, Key{}, fmt.Errorf("keyprovider: read %s: %w", p.Path, err)
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) > 0 {
		return nil, Key{}, fmt.Errorf("keyprovider: %s is not exactly one PKCS#8 PRIVATE KEY PEM block", p.Path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, Key{}, fmt.Errorf("keyprovider: %s: parse PKCS#8: %w", p.Path, err)
	}
	sg, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, Key{}, fmt.Errorf("keyprovider: %s: unsupported key type %T", p.Path, parsed)
	}
	pub := sg.Public()
	alg, err := keys.AlgorithmOf(pub)
	if err != nil || alg != keys.ES256 {
		return nil, Key{}, fmt.Errorf("keyprovider: %s holds %s; only ECDSA P-256 (ES256) is supported", p.Path, describe(pub))
	}
	kid, err := keys.KID(pub)
	if err != nil {
		return nil, Key{}, fmt.Errorf("keyprovider: %s: %w", p.Path, err)
	}
	return sg, Key{KID: kid, Algorithm: keys.ES256, Public: pub}, nil
}

// CreateKeyFile generates an ECDSA P-256 key and writes it at path: a
// temporary file in the same directory at mode 0600, then os.Link to path, so
// an existing file is never replaced (fs.ErrExist). restrict is required: it
// makes the temporary file owner-only (fileacl.OwnerOnly on Windows, where a
// mode means nothing) before any key byte is written, and the access list
// travels with the hard link.
func CreateKeyFile(path string, restrict func(path string) error) error {
	if restrict == nil {
		return fmt.Errorf("keyprovider: create %s: restrict is nil", path)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keyfile-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		_ = tmp.Close()
		return err
	}
	if err := restrict(name); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("keyprovider: restrict %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Link(name, path)
}

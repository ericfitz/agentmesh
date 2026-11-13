package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
)

func noRestrict(string) error { return nil }

func readPlain(path string) ([]byte, error) { return os.ReadFile(path) }

func writePKCS8(t *testing.T, path string, k crypto.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileProviderNextAndSign(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "int.key")
	if err := CreateKeyFile(path, noRestrict); err != nil {
		t.Fatal(err)
	}
	p := FileProvider{Path: path, Read: readPlain}
	if p.Name() != NameFile || NameFile != "file" {
		t.Fatalf("name %q", p.Name())
	}
	k, err := p.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if k.Algorithm != keys.ES256 || k.Ref != "" || k.KID == "" || k.Public == nil {
		t.Fatalf("key %+v", k)
	}
	s, err := p.Signer(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("hello"))
	sig, err := s.SignContext(ctx, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(k.Public.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature does not verify")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.SignContext(cctx, digest[:], crypto.SHA256); err == nil {
		t.Fatal("canceled context signed")
	}
}

func TestFileProviderRefuses(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]struct {
		prep func(path string)
		read func(string) ([]byte, error)
		want string
	}{
		"ed25519": {prep: func(p string) { writePKCS8(t, p, ed) }, read: readPlain, want: "Ed25519"},
		"p384":    {prep: func(p string) { writePKCS8(t, p, p384) }, read: readPlain, want: "P-384"},
		"rsa":     {prep: func(p string) { writePKCS8(t, p, rk) }, read: readPlain, want: "RSA"},
		"empty":   {prep: func(p string) { _ = os.WriteFile(p, nil, 0o600) }, read: readPlain},
		"nilread": {prep: func(p string) {}, read: nil},
		"readerr": {prep: func(p string) {}, read: func(string) ([]byte, error) { return nil, errors.New("boom") }, want: "boom"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".key")
			c.prep(path)
			p := FileProvider{Path: path, Read: c.read}
			_, err := p.Next(ctx)
			if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Next error %v", err)
			}
			_, err = p.Signer(ctx, Key{KID: "x"})
			if err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("Signer error %v", err)
			}
		})
	}
}

func TestFileProviderKeyChanged(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := CreateKeyFile(a, noRestrict); err != nil {
		t.Fatal(err)
	}
	if err := CreateKeyFile(b, noRestrict); err != nil {
		t.Fatal(err)
	}
	ka, err := FileProvider{Path: a, Read: readPlain}.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = FileProvider{Path: b, Read: readPlain}.Signer(ctx, ka)
	if err == nil || !strings.Contains(err.Error(), b) {
		t.Fatalf("error %v", err)
	}
}

func noTemps(t *testing.T, dir string, want int) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != want {
		t.Fatalf("directory holds %d entries, want %d: %v", len(ents), want, ents)
	}
}

func TestCreateKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "int.key")
	if err := CreateKeyFile(path, noRestrict); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	noTemps(t, dir, 1)
	if err := CreateKeyFile(path, noRestrict); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second call: %v", err)
	}
	again, _ := os.ReadFile(path)
	if string(first) != string(again) {
		t.Fatal("file changed")
	}
	noTemps(t, dir, 1)
	if _, err := (FileProvider{Path: path, Read: readPlain}).Next(context.Background()); err != nil {
		t.Fatal(err)
	}

	race := filepath.Join(t.TempDir(), "race.key")
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = CreateKeyFile(race, noRestrict) }()
	}
	wg.Wait()
	wins, exists := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, fs.ErrExist):
			exists++
		default:
			t.Fatalf("unexpected %v", err)
		}
	}
	if wins != 1 || exists != 7 {
		t.Fatalf("wins %d exists %d", wins, exists)
	}
	noTemps(t, filepath.Dir(race), 1)
}

func TestCreateKeyFileRestrict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "int.key")
	var calls []string
	var sizeAtCall int64 = -1
	err := CreateKeyFile(path, func(p string) error {
		calls = append(calls, p)
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		sizeAtCall = fi.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] == path || filepath.Dir(calls[0]) != dir {
		t.Fatalf("restrict calls %v", calls)
	}
	if sizeAtCall != 0 {
		t.Fatalf("temp held %d bytes when restrict ran", sizeAtCall)
	}
	noTemps(t, dir, 1)
}

func TestCreateKeyFileRestrictFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "int.key")
	err := CreateKeyFile(path, func(string) error { return errors.New("acl boom") })
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "acl boom") {
		t.Fatalf("error %v", err)
	}
	noTemps(t, dir, 0)
}

func TestCreateKeyFileNilRestrict(t *testing.T) {
	dir := t.TempDir()
	err := CreateKeyFile(filepath.Join(dir, "int.key"), nil)
	if err == nil || !strings.Contains(err.Error(), "restrict") {
		t.Fatalf("error %v", err)
	}
	noTemps(t, dir, 0)
}

package signingkeys_test

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/keyprovider/kmsfake"
)

func TestConfigured(t *testing.T) {
	ctx := context.Background()
	t.Run("file", func(t *testing.T) {
		e := newEnv(t)
		if ok, err := e.tr.Configured(ctx, e.f.Intermediate, ""); err != nil || !ok {
			t.Fatalf("the key file's certificate: %v, %v", ok, err)
		}
		other := e.f.Sibling(t, "other-installation")
		if ok, err := e.tr.Configured(ctx, other.Intermediate, ""); err != nil || ok {
			t.Fatalf("another key's certificate: %v, %v", ok, err)
		}
		bad := e.tr
		bad.Provider = nil
		if _, err := bad.Configured(ctx, e.f.Intermediate, ""); err == nil {
			t.Fatal("a nil Provider is not an error")
		}
		bad.Provider = keyprovider.FileProvider{Path: filepath.Join(t.TempDir(), "missing.key"), Read: os.ReadFile}
		if _, err := bad.Configured(ctx, e.f.Intermediate, ""); err == nil {
			t.Fatal("an unreadable key file is not an error")
		}
	})
	t.Run("key-service", func(t *testing.T) {
		e := newEnv(t)
		fake := kmsfake.New("")
		e.tr.Provider = fake
		ref := mustNext(t, fake).Ref
		calls := fake.Calls()
		cert := e.f.Intermediate
		if ok, err := e.tr.Configured(ctx, cert, ""); err != nil || ok {
			t.Fatalf("empty key_ref: %v, %v", ok, err)
		}
		if ok, err := e.tr.Configured(ctx, cert, ref); err != nil || !ok {
			t.Fatalf("the fake's own reference: %v, %v", ok, err)
		}
		if ok, err := e.tr.Configured(ctx, cert, "gcpkms://project/key"); err != nil || ok {
			t.Fatalf("another scheme: %v, %v", ok, err)
		}
		if ok, err := e.tr.Configured(ctx, cert, "no-scheme"); err != nil || ok {
			t.Fatalf("a malformed reference: %v, %v", ok, err)
		}
		if fake.Calls() != calls {
			t.Fatalf("the key service was called %d times", fake.Calls()-calls)
		}
	})
}

func mustNext(t *testing.T, p keyprovider.Provider) keyprovider.Key {
	t.Helper()
	k, err := p.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPick(t *testing.T) {
	ctx := context.Background()
	day := 24 * time.Hour
	t.Run("file", func(t *testing.T) {
		pick := func(t *testing.T, e *env, certs ...*x509.Certificate) signingkeys.Picked {
			t.Helper()
			for _, c := range certs {
				e.putIntermediate(t, c, "")
			}
			p, err := e.tr.Pick(ctx, e.load(t))
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
		t.Run("no-match", func(t *testing.T) {
			e := newEnv(t)
			p := pick(t, e, craft(t, e.f, newP256(t).Public(), nil))
			if len(p.Configured) != 0 || p.Use != nil {
				t.Fatalf("%+v", p)
			}
		})
		t.Run("none-stored", func(t *testing.T) {
			e := newEnv(t)
			if p := pick(t, e); len(p.Configured) != 0 || p.Use != nil {
				t.Fatalf("%+v", p)
			}
		})
		t.Run("later-not-before-wins", func(t *testing.T) {
			e := newEnv(t)
			later := e.f.Renew(t, e.clk.now().Add(-10*time.Minute), 30)
			p := pick(t, e, e.f.Intermediate, later)
			if len(p.Configured) != 2 || p.Use == nil || p.Use.SerialNumber.Cmp(later.SerialNumber) != 0 || p.KeyRef != "" {
				t.Fatalf("%+v", p)
			}
		})
		t.Run("not-yet-valid-is-skipped", func(t *testing.T) {
			e := newEnv(t)
			future := e.f.Renew(t, e.clk.now().Add(time.Hour), 30)
			p := pick(t, e, e.f.Intermediate, future)
			if len(p.Configured) != 2 || p.Use == nil || p.Use.SerialNumber.Cmp(e.f.Intermediate.SerialNumber) != 0 {
				t.Fatalf("%+v", p)
			}
		})
		t.Run("expired-newest-is-skipped", func(t *testing.T) {
			e := newEnv(t)
			now := e.clk.now()
			expired := craft(t, e.f, interKey(t, e.f).Public(), func(c *x509.Certificate) {
				c.NotBefore = now.Add(-10 * time.Minute)
				c.NotAfter = now.Add(-time.Minute)
			})
			p := pick(t, e, e.f.Intermediate, expired)
			if len(p.Configured) != 2 || p.Use == nil || p.Use.SerialNumber.Cmp(e.f.Intermediate.SerialNumber) != 0 {
				t.Fatalf("%+v", p)
			}
		})
		t.Run("all-expired", func(t *testing.T) {
			e := newEnv(t)
			now := e.clk.now()
			a := craft(t, e.f, interKey(t, e.f).Public(), func(c *x509.Certificate) {
				c.NotBefore = now.Add(-3 * day)
				c.NotAfter = now.Add(-2 * day)
			})
			b := craft(t, e.f, interKey(t, e.f).Public(), func(c *x509.Certificate) {
				c.NotBefore = now.Add(-day)
				c.NotAfter = now.Add(-time.Hour)
			})
			p := pick(t, e, a, b)
			if p.Use != nil || len(p.Configured) != 2 {
				t.Fatalf("%+v", p)
			}
		})
		t.Run("reads-the-key-file-once", func(t *testing.T) {
			e := newEnv(t)
			reads := 0
			e.tr.Provider = keyprovider.FileProvider{Path: e.f.KeyFile, Read: func(p string) ([]byte, error) {
				reads++
				return os.ReadFile(p)
			}}
			later := e.f.Renew(t, e.clk.now().Add(-10*time.Minute), 30)
			pick(t, e, e.f.Intermediate, later, craft(t, e.f, newP256(t).Public(), nil))
			if reads != 1 {
				t.Fatalf("the key file was read %d times", reads)
			}
		})
	})
	t.Run("key-service", func(t *testing.T) {
		e := newEnv(t)
		fake := kmsfake.New("")
		e.tr.Provider = fake
		pub := mustNext(t, fake).Public
		now := e.clk.now()
		earlier := craft(t, e.f, pub, func(c *x509.Certificate) { c.NotBefore = now.Add(-2 * time.Hour) })
		later := craft(t, e.f, pub, func(c *x509.Certificate) { c.NotBefore = now.Add(-time.Hour) })
		foreign := craft(t, e.f, pub, func(c *x509.Certificate) { c.NotBefore = now.Add(-time.Minute) })
		e.putIntermediate(t, earlier, "awskms://kmsfake/version-1")
		e.putIntermediate(t, later, "awskms://kmsfake/version-7")
		e.putIntermediate(t, foreign, "gcpkms://other/key")
		calls := fake.Calls()
		p, err := e.tr.Pick(ctx, e.load(t))
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Configured) != 2 || p.Use == nil || p.Use.SerialNumber.Cmp(later.SerialNumber) != 0 || p.KeyRef != "awskms://kmsfake/version-7" {
			t.Fatalf("%+v", p)
		}
		if fake.Calls() != calls {
			t.Fatal("Pick called the key service")
		}
	})
}

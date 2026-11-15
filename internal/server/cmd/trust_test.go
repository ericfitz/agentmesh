package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/keyprovider/kmsfake"
	"github.com/ericfitz/agentmesh/internal/server/config"
)

// In the default build no backend is registered, so every scheme is refused
// with its tag name.
func TestOpenIntermediateProviderRefusesSchemeWithoutBackend(t *testing.T) {
	for _, scheme := range keyprovider.Schemes() {
		if _, ok := keyBackends[scheme]; ok {
			continue // a tagged build registered it
		}
		_, err := openIntermediateProvider(config.Config{IntermediateKeyURI: scheme + "://x"})
		want := "intermediate_key_uri: the " + scheme + " backend is not in this build (build with -tags " + scheme + ")"
		if err == nil || err.Error() != want {
			t.Errorf("%s: err %v, want %q", scheme, err, want)
		}
	}
}

func TestOpenIntermediateProviderUsesRegisteredBackend(t *testing.T) {
	var got string
	setBackend(t, "awskms", func(uri string) (keyprovider.Provider, error) {
		got = uri
		return stubProvider{}, nil
	})
	p, err := openIntermediateProvider(config.Config{IntermediateKeyURI: "awskms://k"})
	if err != nil || p.Name() != "awskms" || got != "awskms://k" {
		t.Fatalf("provider %v, err %v, uri %q", p, err, got)
	}
}

func TestOpenIntermediateProviderRejectsUnknownOrMissingScheme(t *testing.T) {
	for _, uri := range []string{"gcs://x", "", "no-scheme"} {
		_, err := openIntermediateProvider(config.Config{IntermediateKeyURI: uri})
		if err == nil || !strings.Contains(err.Error(), "intermediate_key_uri") {
			t.Errorf("%q: err %v", uri, err)
		}
	}
}

// stubProvider stands in for an external backend (kmsfake arrives later).
type stubProvider struct{}

func (stubProvider) Name() string { return "awskms" }
func (stubProvider) Next(context.Context) (keyprovider.Key, error) {
	return keyprovider.Key{}, errors.New("stub: no key")
}
func (stubProvider) Signer(context.Context, keyprovider.Key) (keyprovider.Signer, error) {
	return nil, errors.New("stub: no signer")
}

// useFake registers f as the awskms backend for the test.
func useFake(t *testing.T, f *kmsfake.Fake) {
	t.Helper()
	setBackend(t, "awskms", func(string) (keyprovider.Provider, error) { return f, nil })
}

// setBackend registers open for scheme (nil removes it) and restores what was
// there, so a tagged build's init registration survives the test.
func setBackend(t *testing.T, scheme string, open func(string) (keyprovider.Provider, error)) {
	t.Helper()
	prev, had := keyBackends[scheme]
	if open == nil {
		delete(keyBackends, scheme)
	} else {
		keyBackends[scheme] = open
	}
	t.Cleanup(func() {
		if had {
			keyBackends[scheme] = prev
		} else {
			delete(keyBackends, scheme)
		}
	})
}

// Rotate opens the provider like the start does: a configuration error is exit
// 2, a provider that reports the service down stays exit 1.
func TestAdminRotateExitCodesForProviderFailures(t *testing.T) {
	rotate := func(t *testing.T, uri string) (int, string) {
		t.Helper()
		e := newCAEnv(t)
		code, _, errOut := e.run(append(e.settings("intermediate_key_uri="+uri), "signing-key", "rotate")...)
		return code, errOut
	}
	t.Run("a backend not in this build", func(t *testing.T) {
		setBackend(t, "awskms", nil)
		if code, errOut := rotate(t, "awskms://alias/agentmesh"); code != 2 || !strings.Contains(errOut, "not in this build") {
			t.Fatalf("exit %d, stderr %q; want 2", code, errOut)
		}
	})
	t.Run("a malformed URI", func(t *testing.T) {
		setBackend(t, "awskms", func(string) (keyprovider.Provider, error) { return nil, errors.New("bad key URI") })
		if code, errOut := rotate(t, "awskms://alias/agentmesh"); code != 2 || !strings.Contains(errOut, "bad key URI") {
			t.Fatalf("exit %d, stderr %q; want 2", code, errOut)
		}
	})
	t.Run("the service is unreachable", func(t *testing.T) {
		setBackend(t, "awskms", func(string) (keyprovider.Provider, error) {
			return nil, fmt.Errorf("dial: %w", keyprovider.ErrUnavailable)
		})
		if code, errOut := rotate(t, "awskms://alias/agentmesh"); code != 1 {
			t.Fatalf("exit %d, stderr %q; want 1", code, errOut)
		}
	})
}

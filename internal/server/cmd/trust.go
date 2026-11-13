package cmd

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/fileacl"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/server/config"
)

// openRoot reads root_certificate_file: one PEM certificate that passes
// pki.CheckRoot (Plan ruling 32). An outside CA's root, an RSA one included,
// passes; a certificate that is not a CA does not.
func openRoot(cfg config.Config) (*x509.Certificate, error) {
	b, err := os.ReadFile(cfg.RootCertificateFile)
	if err != nil {
		return nil, fmt.Errorf("root_certificate_file: %w", err)
	}
	root, err := pki.ParseCertificatePEM(b)
	if err != nil {
		return nil, fmt.Errorf("root_certificate_file %s: %w", cfg.RootCertificateFile, err)
	}
	if err := pki.CheckRoot(root); err != nil {
		return nil, fmt.Errorf("root_certificate_file %s: %w", cfg.RootCertificateFile, err)
	}
	return root, nil
}

// openIntermediateProvider is the FileProvider of intermediate_key_file, or
// the backend of intermediate_key_uri from keyBackends (a scheme not in this
// build names its build tag). Neither makes a network call or reads the key.
func openIntermediateProvider(cfg config.Config) (keyprovider.Provider, error) {
	if cfg.IntermediateKeyFile != "" {
		return keyprovider.FileProvider{Path: cfg.IntermediateKeyFile, Read: readOwnerOnly}, nil
	}
	scheme, err := keyprovider.SchemeOf(cfg.IntermediateKeyURI)
	if err != nil {
		return nil, fmt.Errorf("intermediate_key_uri: %w", err)
	}
	if scheme == "" {
		return nil, errors.New("intermediate_key_uri: has no scheme; want one of awskms, gcpkms, azurekms, hashivault")
	}
	open, ok := keyBackends[scheme]
	if !ok {
		return nil, fmt.Errorf("intermediate_key_uri: the %s backend is not in this build (build with -tags %s)", scheme, scheme)
	}
	return open(cfg.IntermediateKeyURI)
}

// newTrust is hostEnv.Trust: the trust rules over c for the configured root,
// installation name and key. Every requirement and file failure is a
// *configError (exit 2); a key service outage is not (exit 1). sign false
// leaves Provider nil, so nothing opens or reads the key.
func newTrust(c *core.Core, cfg config.Config) func(sign bool) (signingkeys.Trust, error) {
	return func(sign bool) (signingkeys.Trust, error) {
		if err := cfg.RequireTrust(); err != nil {
			return signingkeys.Trust{}, &configError{err}
		}
		root, err := openRoot(cfg)
		if err != nil {
			return signingkeys.Trust{}, &configError{err}
		}
		t := signingkeys.Trust{Core: c, Root: root, Installation: cfg.InstallationName}
		if !sign {
			return t, nil
		}
		if t.Provider, err = openIntermediateProvider(cfg); err != nil {
			if errors.Is(err, keyprovider.ErrUnavailable) {
				return signingkeys.Trust{}, err
			}
			return signingkeys.Trust{}, &configError{err}
		}
		return t, nil
	}
}

// trustFailure maps a trust rule's error to an exit: a refused check
// (ErrCheck) and, with the file form, a key file that cannot be used are exit
// 2; a Store or key service failure keeps its own error (exit 1).
func trustFailure(cfg config.Config, err error) error {
	var be *bus.Error
	switch {
	case err == nil:
		return nil
	case errors.Is(err, signingkeys.ErrCheck):
		return &configError{err}
	case errors.As(err, &be):
		return err
	case cfg.IntermediateKeyFile != "" && !errors.Is(err, keyprovider.ErrUnavailable):
		return &configError{err}
	}
	return err
}

// ownerOnlyRestrict is what ca csr hands keyprovider.CreateKeyFile.
var ownerOnlyRestrict = fileacl.OwnerOnly

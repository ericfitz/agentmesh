package signingkeys

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

// closeError maps what a transaction returned: a refusal stays an ErrCheck
// error, every other error is a Store error.
func closeError(err error) error {
	if err == nil || errors.Is(err, ErrCheck) {
		return err
	}
	return core.FromStore(err)
}

// InstallIntermediate stores an intermediate certificate after the checks of
// section 4.4, each wrapping ErrCheck. changed is false when the thumbprint is
// already stored.
func (t Trust) InstallIntermediate(ctx context.Context, cert *x509.Certificate) (changed bool, err error) {
	if err := pki.CheckIntermediate(cert, t.Root, t.Installation); err != nil {
		return false, fmt.Errorf("%w: %w", ErrCheck, err)
	}
	now := t.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false, refuse("the intermediate certificate is not valid now (valid from %s to %s)",
			cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"), cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	}
	key, err := t.nextKey(ctx)
	if err != nil {
		return false, err
	}
	if !samePublic(key.Public, cert.PublicKey) {
		return false, refuse("its public key is not the configured intermediate key")
	}
	err = t.withLock(ctx, func(func(context.Context) error) error {
		return t.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			changed = false
			rows, err := tx.TrustCertificates(ctx, store.TrustIntermediate)
			if err != nil {
				return err
			}
			certs := []*x509.Certificate{cert}
			for _, r := range rows {
				c, perr := x509.ParseCertificate(r.DER)
				if perr != nil {
					continue
				}
				if samePublic(c.PublicKey, cert.PublicKey) && !bytes.Equal(c.SubjectKeyId, cert.SubjectKeyId) {
					return refuse("its subject key identifier differs from the stored certificates of the same key")
				}
				certs = append(certs, c)
			}
			crls, err := tx.CRLs(ctx)
			if err != nil {
				return err
			}
			for _, r := range crls {
				if r.Kind != store.TrustRootCRL {
					continue
				}
				crl, perr := parseStoredCRL(r)
				if perr == nil {
					perr = pki.CheckCRL(crl, t.Root)
				}
				if perr != nil {
					continue
				}
				var rev pki.Revocations
				rev.AddRoot(crl)
				if rev.RevokedKeys(certs)[pki.KeyID(cert.SubjectKeyId)] {
					return refuse("its key is revoked by the stored root CRL")
				}
			}
			thumb := pki.Thumbprint(cert.Raw)
			if _, ok, err := tx.TrustCertificateByThumbprint(ctx, store.TrustIntermediate, thumb); err != nil || ok {
				return err
			}
			if _, err := tx.PutTrustCertificate(ctx, store.TrustCertificate{
				Kind: store.TrustIntermediate, Thumbprint: thumb, DER: cert.Raw,
				NotAfter: cert.NotAfter.UnixMilli(), KeyRef: key.Ref, CreatedAt: t.NowMs(),
			}); err != nil {
				return err
			}
			if _, err := tx.BumpTrustNumber(ctx, t.NowMs()); err != nil {
				return err
			}
			changed = true
			return nil
		})
	})
	if err != nil {
		return false, closeError(err)
	}
	return changed, nil
}

// InstallRootCRL stores a root CRL signed by the pinned root. changed is false
// when it is the stored one; a number not above the stored one is refused.
func (t Trust) InstallRootCRL(ctx context.Context, crl *x509.RevocationList) (changed bool, err error) {
	if crl == nil || len(crl.Raw) == 0 {
		return false, refuse("there is no CRL")
	}
	if err := pki.CheckCRL(crl, t.Root); err != nil {
		return false, refuse("the CRL is not signed by the pinned root: %v", err)
	}
	number := pki.CRLNumber(crl)
	if number <= 0 {
		return false, refuse("the CRL has no usable CRL number")
	}
	thumb := pki.Thumbprint(crl.Raw)
	err = t.withLock(ctx, func(func(context.Context) error) error {
		return t.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			changed = false
			rows, err := tx.CRLs(ctx)
			if err != nil {
				return err
			}
			for _, r := range rows {
				if r.Kind != store.TrustRootCRL {
					continue
				}
				if r.Thumbprint == thumb {
					return nil
				}
				if number <= r.Number {
					return refuse("number %d is not above the stored %d", number, r.Number)
				}
			}
			if err := tx.PutCRL(ctx, store.TrustCRL{
				Kind: store.TrustRootCRL, Thumbprint: thumb, DER: crl.Raw, Number: number, CreatedAt: t.NowMs(),
			}); err != nil {
				return err
			}
			if _, err := tx.BumpTrustNumber(ctx, t.NowMs()); err != nil {
				return err
			}
			changed = true
			return nil
		})
	})
	if err != nil {
		return false, closeError(err)
	}
	return changed, nil
}

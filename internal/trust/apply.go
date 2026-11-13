package trust

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ericfitz/agentmesh/internal/pki"
)

// RefusedCRL is a CRL refused for a number below the held one. IssuerKey is ""
// for the root CRL.
type RefusedCRL struct {
	IssuerKey string
	Held, Got int64
}

// Report is what Apply refused.
type Report struct{ Refused []RefusedCRL }

// Apply is steps 2 to 5 of section 4.9 against the pin. It needs a pin (an
// error without one). A second Apply of the same bundle changes no file.
func (s Store) Apply(b Bundle) (Report, error) {
	var rep Report
	err := s.withLock(false, func() error {
		pin, ok, err := s.pin()
		if err != nil {
			return err
		}
		if !ok {
			return s.noPin()
		}
		kept, err := s.keepIntermediates(b, pin)
		if err != nil {
			return err
		}
		revs, err := s.heldRevocations()
		if err != nil {
			return err
		}
		type crlWrite struct {
			name string
			der  []byte
		}
		var crls []crlWrite

		// Step 3: the root CRL.
		if len(b.RootCRL) > 0 {
			if crl, err := pki.ParseCRL(b.RootCRL); err == nil && pki.CheckCRL(crl, pin.Root) == nil {
				held, has, err := s.heldCRLNumber(rootCRLFile)
				if err != nil {
					return err
				}
				if got := pki.CRLNumber(crl); has && got < held {
					rep.Refused = append(rep.Refused, RefusedCRL{Held: held, Got: got})
				} else {
					revs.AddRoot(crl)
					crls = append(crls, crlWrite{rootCRLFile, b.RootCRL})
				}
			}
		}

		// Step 4: leaf CRLs, against the intermediates kept and the keys the
		// root CRL (as just kept) has revoked.
		revoked := revs.RevokedKeys(kept)
		for _, der := range b.LeafCRLs {
			crl, err := pki.ParseCRL(der)
			if err != nil {
				continue
			}
			for _, c := range kept {
				key := pki.KeyID(c.SubjectKeyId)
				if revoked[key] || pki.CheckCRL(crl, c) != nil {
					continue
				}
				held, has, err := s.heldCRLNumber(leafCRLName(key))
				if err != nil {
					return err
				}
				if got := pki.CRLNumber(crl); has && got < held {
					rep.Refused = append(rep.Refused, RefusedCRL{IssuerKey: key, Held: held, Got: got})
				} else {
					revs.AddLeaves(key, crl)
					crls = append(crls, crlWrite{leafCRLName(key), der})
				}
				break
			}
		}

		// Writes: the kept revocations before the CRL files, so a kill between
		// them leaves the revocations kept and the CRL to be taken again.
		rb, err := json.MarshalIndent(revs, "", "  ")
		if err != nil {
			return err
		}
		if err := s.writeIfChanged(revokedFile, append(rb, '\n')); err != nil {
			return err
		}
		for _, w := range crls {
			if err := s.writeIfChanged(w.name, pki.EncodePEM(crlPEMType, w.der)); err != nil {
				return err
			}
		}

		// Step 5: the trust number, higher or lower.
		st, err := s.loadState()
		if err != nil {
			return err
		}
		if st.TrustNumber == nil || *st.TrustNumber != b.TrustNumber {
			n := b.TrustNumber
			st.TrustNumber = &n
			return s.saveState(st)
		}
		return nil
	})
	if errors.Is(err, errNoDir) {
		err = s.noPin()
	}
	if err != nil {
		return Report{}, err
	}
	return rep, nil
}

func (s Store) noPin() error {
	return fmt.Errorf("trust: no root is pinned in %s", s.Dir)
}

// keepIntermediates is step 2: the held ones plus each bundle intermediate
// that passes CheckIntermediate against the pin; none is ever dropped.
func (s Store) keepIntermediates(b Bundle, pin Pin) ([]*x509.Certificate, error) {
	held, err := s.heldIntermediates()
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, c := range held {
		have[pki.Thumbprint(c.Raw)] = true
	}
	kept := held
	for _, der := range b.Intermediates {
		c, err := x509.ParseCertificate(der)
		if err != nil || have[pki.Thumbprint(c.Raw)] {
			continue
		}
		if pki.CheckIntermediate(c, pin.Root, pin.Installation) != nil {
			continue
		}
		have[pki.Thumbprint(c.Raw)] = true
		kept = append(kept, c)
	}
	if len(kept) != len(held) {
		if err := s.writeFile(intermediatesFile, encodeCertsPEM(kept)); err != nil {
			return nil, err
		}
	}
	return kept, nil
}

func (s Store) heldIntermediates() ([]*x509.Certificate, error) {
	b, err := s.readFile(intermediatesFile)
	if err != nil || b == nil {
		return nil, err
	}
	cs, err := parseCertsPEM(b)
	if err != nil {
		return nil, fmt.Errorf("trust: %s: %w", s.path(intermediatesFile), err)
	}
	return cs, nil
}

func (s Store) heldRevocations() (pki.Revocations, error) {
	var r pki.Revocations
	b, err := s.readFile(revokedFile)
	if err != nil || b == nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return pki.Revocations{}, fmt.Errorf("trust: parse %s: %w", s.path(revokedFile), err)
	}
	return r, nil
}

// TrustNumber is the held trust number; ok is false before any bundle has been
// applied.
func (s Store) TrustNumber() (n int64, ok bool, err error) {
	err = s.read(func() error {
		st, err := s.loadState()
		if err != nil || st == nil || st.TrustNumber == nil {
			return err
		}
		n, ok = *st.TrustNumber, true
		return nil
	})
	return n, ok, err
}

// Intermediates are the kept intermediates.
func (s Store) Intermediates() (cs []*x509.Certificate, err error) {
	err = s.read(func() (e error) { cs, e = s.heldIntermediates(); return })
	return cs, err
}

// Revocations are the kept revocations.
func (s Store) Revocations() (r pki.Revocations, err error) {
	err = s.read(func() (e error) { r, e = s.heldRevocations(); return })
	return r, err
}

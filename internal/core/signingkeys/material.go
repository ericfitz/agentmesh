package signingkeys

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

// chainCheckHook, when set (export_test.go), is called before every chain
// verification Load makes.
var chainCheckHook func()

type chainKey struct{ leaf, intermediate string }

type chainResult struct {
	v   pki.Verified
	err error
}

type memCRL struct {
	row store.TrustCRL
	crl *x509.RevocationList
}

// Memory is what one process remembers between loads (section 4.8): the
// highest number it has verified for each CRL with that CRL's bytes, the kept
// revocations, and the chains it has already verified. The zero value is
// ready; it is not safe for concurrent use (the manager guards its own with a
// mutex; a host command uses a fresh one).
type Memory struct {
	crls    map[string]memCRL
	revoked pki.Revocations
	chains  map[chainKey]chainResult
	logged  map[string]bool
}

// Leaf is a stored leaf whose chain verifies.
type Leaf struct {
	ID       int64
	Verified pki.Verified
	Revoked  bool
}

// Material is the verified view of the stored rows.
type Material struct {
	Number        int64                           // read in the same transaction as the rows
	Intermediates []*x509.Certificate             // every stored one that passes pki.CheckIntermediate, in row order
	KeyRefs       map[string]string               // intermediate thumbprint -> key_ref
	RootCRL       *x509.RevocationList            // nil: none
	LeafCRLs      map[string]*x509.RevocationList // by issuer key
	Leaves        []Leaf                          // every leaf row whose chain verifies, in row order
	Revoked       pki.Revocations                 // the union this process holds
	RevokedKeys   map[string]bool
	Rollback      []store.TrustCRL // CRLs this process holds that are newer than the stored ones
}

func thumbprintOf(c *x509.Certificate) string { return pki.Thumbprint(c.Raw) }

// ignore logs a row that does not verify, once per process and row.
func (t Trust) ignore(mem *Memory, kind, thumbprint string, reason error) {
	key := kind + "/" + thumbprint
	if mem.logged[key] {
		return
	}
	mem.logged[key] = true
	t.Log.Warn("trust material ignored", "kind", kind, "thumbprint", thumbprint, "reason", reason.Error())
}

// parseCertificate parses a row's DER and checks its thumbprint column.
func parseCertificate(thumbprint string, der []byte) (*x509.Certificate, error) {
	if pki.Thumbprint(der) != thumbprint {
		return nil, errors.New("the thumbprint column is not the thumbprint of the DER")
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return c, nil
}

func parseStoredCRL(row store.TrustCRL) (*x509.RevocationList, error) {
	if pki.Thumbprint(row.DER) != row.Thumbprint {
		return nil, errors.New("the thumbprint column is not the thumbprint of the DER")
	}
	crl, err := pki.ParseCRL(row.DER)
	if err != nil {
		return nil, err
	}
	if pki.CRLNumber(crl) != row.Number {
		return nil, errors.New("the number column is not the CRL's number")
	}
	return crl, nil
}

// Load reads the rows in one Store.Read and verifies each against the pinned
// root. A row that does not verify is ignored and logged once with its kind
// and thumbprint; only a Store failure is an error.
func (t Trust) Load(ctx context.Context, mem *Memory) (Material, error) {
	if mem == nil {
		mem = &Memory{}
	}
	if mem.crls == nil {
		mem.crls = map[string]memCRL{}
		mem.chains = map[chainKey]chainResult{}
		mem.logged = map[string]bool{}
	}
	var (
		number             int64
		inters, leafRows   []store.TrustCertificate
		crlRows            []store.TrustCRL
		m                  = Material{KeyRefs: map[string]string{}, LeafCRLs: map[string]*x509.RevocationList{}}
		stored, rolledBack = map[string]bool{}, map[string]bool{}
		chainsSeen         = map[chainKey]chainResult{}
	)
	err := t.Store.Read(ctx, func(ctx context.Context, tx store.Tx) error {
		var err error
		if number, err = tx.TrustNumber(ctx); err != nil {
			return err
		}
		if inters, err = tx.TrustCertificates(ctx, store.TrustIntermediate); err != nil {
			return err
		}
		if leafRows, err = tx.TrustCertificates(ctx, store.TrustLeaf); err != nil {
			return err
		}
		crlRows, err = tx.CRLs(ctx)
		return err
	})
	if err != nil {
		return Material{}, core.FromStore(err)
	}
	m.Number = number

	for _, row := range inters {
		cert, err := parseCertificate(row.Thumbprint, row.DER)
		if err == nil {
			err = pki.CheckIntermediate(cert, t.Root, t.Installation)
		}
		if err != nil {
			t.ignore(mem, store.TrustIntermediate, row.Thumbprint, err)
			continue
		}
		m.Intermediates = append(m.Intermediates, cert)
		m.KeyRefs[row.Thumbprint] = row.KeyRef
	}

	// take applies the memory rule to a verified CRL: an older number than the
	// one this process holds is a rollback and the newer one stays in force.
	take := func(key string, row store.TrustCRL, crl *x509.RevocationList, add func(*x509.RevocationList)) *x509.RevocationList {
		stored[key] = true
		if cur, ok := mem.crls[key]; ok && cur.row.Number > row.Number {
			t.rollback(mem, row, cur.row)
			rolledBack[key] = true
			m.Rollback = append(m.Rollback, cur.row)
			return cur.crl
		}
		mem.crls[key] = memCRL{row: row, crl: crl}
		add(crl)
		return crl
	}

	for _, row := range crlRows {
		if row.Kind != store.TrustRootCRL {
			continue
		}
		crl, err := parseStoredCRL(row)
		if err == nil {
			err = pki.CheckCRL(crl, t.Root)
		}
		if err != nil {
			t.ignore(mem, store.TrustRootCRL, row.Thumbprint, err)
			continue
		}
		m.RootCRL = take("root", row, crl, mem.revoked.AddRoot)
	}
	if !stored["root"] {
		if cur, ok := mem.crls["root"]; ok {
			t.rollbackMissing(mem, cur.row)
			m.RootCRL = cur.crl
			m.Rollback = append(m.Rollback, cur.row)
		}
	}
	revokedKeys := mem.revoked.RevokedKeys(m.Intermediates)

	byKey := map[string][]*x509.Certificate{}
	for _, c := range m.Intermediates {
		byKey[keyIDOf(c)] = append(byKey[keyIDOf(c)], c)
	}
	for _, row := range crlRows {
		if row.Kind != store.TrustLeafCRL {
			continue
		}
		crl, err := parseStoredCRL(row)
		if err == nil {
			err = checkLeafCRL(crl, byKey[row.IssuerKey], revokedKeys[row.IssuerKey])
		}
		if err != nil {
			t.ignore(mem, store.TrustLeafCRL, row.Thumbprint, err)
			continue
		}
		issuer := row.IssuerKey
		m.LeafCRLs[issuer] = take("leaf/"+issuer, row, crl, func(c *x509.RevocationList) { mem.revoked.AddLeaves(issuer, c) })
	}
	for key, cur := range mem.crls {
		issuer, ok := leafIssuer(key)
		if !ok || stored[key] || rolledBack[key] || len(byKey[issuer]) == 0 {
			continue
		}
		t.rollbackMissing(mem, cur.row)
		m.LeafCRLs[issuer] = cur.crl
		m.Rollback = append(m.Rollback, cur.row)
	}

	m.Revoked.Merge(mem.revoked)
	m.RevokedKeys = m.Revoked.RevokedKeys(m.Intermediates)

	for _, row := range leafRows {
		leaf, err := parseCertificate(row.Thumbprint, row.DER)
		var best pki.Verified
		found := false
		if err == nil {
			err = fmt.Errorf("no stored intermediate has the issuer key %q", row.IssuerKey)
			for _, im := range byKey[row.IssuerKey] {
				ck := chainKey{row.Thumbprint, thumbprintOf(im)}
				res, ok := mem.chains[ck]
				if !ok {
					if chainCheckHook != nil {
						chainCheckHook()
					}
					v, cerr := pki.CheckChain([]*x509.Certificate{leaf, im}, t.Root, t.Installation)
					res = chainResult{v: v, err: cerr}
				}
				chainsSeen[ck] = res
				if res.err != nil {
					err = res.err
					continue
				}
				if !found || res.v.NotAfter.After(best.NotAfter) {
					best, found = res.v, true
				}
			}
		}
		if !found {
			t.ignore(mem, store.TrustLeaf, row.Thumbprint, err)
			continue
		}
		m.Leaves = append(m.Leaves, Leaf{ID: row.ID, Verified: best, Revoked: m.Revoked.LeafRevoked(leaf, m.Intermediates)})
	}
	mem.chains = chainsSeen
	return m, nil
}

func keyIDOf(c *x509.Certificate) string { return pki.KeyID(c.SubjectKeyId) }

func leafIssuer(key string) (string, bool) {
	const p = "leaf/"
	if len(key) > len(p) && key[:len(p)] == p {
		return key[len(p):], true
	}
	return "", false
}

// checkLeafCRL verifies a leaf CRL against the kept intermediates of its issuer
// key: the key must not be revoked and one certificate of it must have been
// valid at the CRL's "this update".
func checkLeafCRL(crl *x509.RevocationList, issuers []*x509.Certificate, revoked bool) error {
	if len(issuers) == 0 {
		return errors.New("no stored intermediate has the issuer key")
	}
	if revoked {
		return errors.New("the issuer key is revoked")
	}
	var err error
	for _, c := range issuers {
		if err = pki.CheckCRL(crl, c); err == nil {
			return nil
		}
	}
	return err
}

func (t Trust) rollback(mem *Memory, stored, held store.TrustCRL) {
	key := fmt.Sprintf("rollback/%s/%s/%d", stored.Kind, stored.IssuerKey, stored.Number)
	if mem.logged[key] {
		return
	}
	mem.logged[key] = true
	t.Log.Warn("trust material rollback: the stored CRL is older than one this process verified",
		"kind", stored.Kind, "thumbprint", stored.Thumbprint, "stored_number", stored.Number,
		"held_thumbprint", held.Thumbprint, "held_number", held.Number)
}

func (t Trust) rollbackMissing(mem *Memory, held store.TrustCRL) {
	key := fmt.Sprintf("rollback-missing/%s/%s/%d", held.Kind, held.IssuerKey, held.Number)
	if mem.logged[key] {
		return
	}
	mem.logged[key] = true
	t.Log.Warn("trust material rollback: a CRL this process verified is no longer stored",
		"kind", held.Kind, "held_thumbprint", held.Thumbprint, "held_number", held.Number)
}

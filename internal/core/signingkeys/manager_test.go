package signingkeys_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/keyprovider/kmsfake"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

const week = 168 * time.Hour

func (e *env) newManager(t *testing.T) *signingkeys.Manager {
	t.Helper()
	m, err := signingkeys.New(context.Background(), signingkeys.Options{Trust: e.tr, LeafValidity: week})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// coreOver is another core over st on e's clock: a second process.
func (e *env) coreOver(t *testing.T, st store.Store) *core.Core {
	t.Helper()
	c, err := core.New(st, core.Defaults(), core.Options{Now: e.clk.now, Logger: slog.New(slog.NewTextHandler(e.logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) leafRows(t *testing.T) []store.TrustCertificate { return e.rows(t, store.TrustLeaf) }

func TestNewIssuesFirstLeaf(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	before := e.trustNumber(t)
	m := e.newManager(t)

	rows := e.leafRows(t)
	if len(rows) != 1 {
		t.Fatalf("%d leaf rows, want 1", len(rows))
	}
	row := rows[0]
	leaf, err := x509.ParseCertificate(row.DER)
	if err != nil {
		t.Fatal(err)
	}
	now := e.clk.now()
	if !leaf.NotBefore.Equal(now.Add(-60*time.Second)) || !leaf.NotAfter.Equal(now.Add(week)) {
		t.Fatalf("validity %s to %s, now %s", leaf.NotBefore, leaf.NotAfter, now)
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		t.Fatalf("leaf key is %T, want Ed25519", leaf.PublicKey)
	}
	if _, err := pki.VerifyChain([]*x509.Certificate{leaf, e.f.Intermediate}, e.f.Root, e.f.Installation, now, token.Leeway); err != nil {
		t.Fatalf("chain: %v", err)
	}
	if row.IssuerKey != keyID(e.f.Intermediate) || row.Thumbprint != pki.Thumbprint(leaf.Raw) || row.NotAfter != leaf.NotAfter.UnixMilli() {
		t.Fatalf("row = %+v", row)
	}
	tp, na := m.Current()
	if tp != row.Thumbprint || !na.Equal(leaf.NotAfter) {
		t.Fatalf("Current = %q, %s; want %q, %s", tp, na, row.Thumbprint, leaf.NotAfter)
	}
	if after := e.trustNumber(t); after != before {
		t.Fatalf("the trust number moved from %d to %d", before, after)
	}
}

func TestNewRefusesBadOptions(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	noProvider := e.tr
	noProvider.Provider = nil
	for name, o := range map[string]signingkeys.Options{
		"no-provider":  {Trust: noProvider, LeafValidity: week},
		"validity-1h":  {Trust: e.tr, LeafValidity: time.Hour},
		"validity-0":   {Trust: e.tr},
		"validity-721": {Trust: e.tr, LeafValidity: 721 * time.Hour},
	} {
		if _, err := signingkeys.New(context.Background(), o); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if n := len(e.leafRows(t)); n != 0 {
		t.Fatalf("a refused start left %d leaf rows", n)
	}
	for _, v := range []time.Duration{2 * time.Hour, 720 * time.Hour} {
		if _, err := signingkeys.New(context.Background(), signingkeys.Options{Trust: e.tr, LeafValidity: v}); err != nil {
			t.Errorf("validity %s: %v", v, err)
		}
	}
}

func TestNewStartStates(t *testing.T) {
	ctx := context.Background()
	start := func(e *env) error {
		_, err := signingkeys.New(ctx, signingkeys.Options{Trust: e.tr, LeafValidity: week})
		return err
	}
	noLeaf := func(t *testing.T, e *env) {
		t.Helper()
		if n := len(e.leafRows(t)); n != 0 {
			t.Fatalf("%d leaf rows after a refused start", n)
		}
	}
	t.Run("no-intermediate", func(t *testing.T) {
		e := newEnv(t)
		for _, step := range []string{"empty store", "a row for another key"} {
			if step != "empty store" {
				e.putIntermediate(t, craft(t, e.f, newP256(t).Public(), nil), "")
			}
			err := start(e)
			if !errors.Is(err, signingkeys.ErrNoIntermediate) {
				t.Fatalf("%s: err = %v", step, err)
			}
			for _, want := range []string{"agentmesh server admin ca csr", "ca install"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("%s: %q does not name %q", step, err, want)
				}
			}
			noLeaf(t, e)
		}
	})
	t.Run("expired", func(t *testing.T) {
		e := newEnv(t)
		now := e.clk.now()
		e.putIntermediate(t, craft(t, e.f, interKey(t, e.f).Public(), func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
		}), "")
		if err := start(e); !errors.Is(err, signingkeys.ErrIntermediateExpired) {
			t.Fatalf("err = %v", err)
		}
		noLeaf(t, e)
	})
	t.Run("revoked", func(t *testing.T) {
		e := newEnv(t)
		e.f.Install(t, e.c)
		if _, err := e.tr.InstallRootCRL(ctx, e.f.RevokeIntermediate(t, e.clk.now())); err != nil {
			t.Fatal(err)
		}
		if err := start(e); !errors.Is(err, signingkeys.ErrIntermediateRevoked) {
			t.Fatalf("err = %v", err)
		}
		noLeaf(t, e)
	})
	t.Run("root-expired", func(t *testing.T) {
		e := newEnv(t)
		e.f.Install(t, e.c)
		e.clk.advance(e.f.Root.NotAfter.Sub(e.clk.now()) + time.Hour)
		if err := start(e); !errors.Is(err, signingkeys.ErrRootExpired) {
			t.Fatalf("err = %v", err)
		}
		noLeaf(t, e)
	})
	t.Run("key-service-down", func(t *testing.T) {
		e := newEnv(t)
		fake := kmsfake.New("")
		e.tr.Provider = fake
		if _, err := e.tr.InstallIntermediate(ctx, craft(t, e.f, mustNext(t, fake).Public, nil)); err != nil {
			t.Fatal(err)
		}
		fake.SetDown(true)
		if err := start(e); !errors.Is(err, keyprovider.ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
		noLeaf(t, e)
		fake.SetDown(false)
		if err := start(e); err != nil {
			t.Fatalf("after the service came back: %v", err)
		}
	})
	t.Run("pinned-reference-signs-with-another-key", func(t *testing.T) {
		e := newEnv(t)
		fake := kmsfake.New("")
		e.tr.Provider = fake
		cert := craft(t, e.f, mustNext(t, fake).Public, nil)
		e.putIntermediate(t, cert, fake.Repoint().Ref) // the row pins the second version
		err := start(e)
		if err == nil || !strings.Contains(err.Error(), "the configured key is not the certificate's key") {
			t.Fatalf("err = %v", err)
		}
		if !e.logged("the configured key is not the certificate's key") {
			t.Fatalf("not logged: %s", e.logs.String())
		}
		noLeaf(t, e)
	})
}

func TestNewPicksNewestValidIntermediate(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	renewed := e.f.Renew(t, e.clk.now(), 2) // the same key, valid for 2 days
	if _, err := e.tr.InstallIntermediate(ctx, renewed); err != nil {
		t.Fatal(err)
	}
	e.newManager(t)
	rows := e.leafRows(t)
	if len(rows) != 1 {
		t.Fatalf("%d leaf rows", len(rows))
	}
	leaf, err := x509.ParseCertificate(rows[0].DER)
	if err != nil {
		t.Fatal(err)
	}
	if string(leaf.AuthorityKeyId) != string(e.f.Intermediate.SubjectKeyId) || rows[0].IssuerKey != keyID(e.f.Intermediate) {
		t.Fatal("the leaf's authority changed with the renewal")
	}
	if !leaf.NotAfter.Equal(renewed.NotAfter) {
		t.Fatalf("not after %s, want the newer certificate's %s", leaf.NotAfter, renewed.NotAfter)
	}
	if !leaf.NotAfter.Before(e.clk.now().Add(week)) {
		t.Fatal("the leaf was not cut")
	}
}

func hasKey(s token.KeySet, thumb string) bool {
	for _, k := range s.Keys {
		if k.KID == thumb {
			return true
		}
	}
	return false
}

func kids(s token.KeySet) []string {
	var out []string
	for _, k := range s.Keys {
		out = append(out, k.KID)
	}
	return out
}

func TestLoadKeysPublishesVerifiedLeaves(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	ma := e.newManager(t)
	e2 := *e
	e2.c = e.coreOver(t, e.st)
	e2.tr = e.f.Trust(e2.c)
	mb := e2.newManager(t)

	// A self-signed leaf row, put in by hand.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := e.clk.now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: randSerial(t), Subject: pkix.Name{CommonName: "agentmesh leaf"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}, &x509.Certificate{SerialNumber: randSerial(t)}, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	selfSigned, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	e.putLeaf(t, selfSigned, keyID(e.f.Intermediate))

	ta, _ := ma.Current()
	tb, _ := mb.Current()
	if ta == "" || ta == tb {
		t.Fatalf("the managers' leaves are %q and %q", ta, tb)
	}
	for name, tc := range map[string]struct {
		m   *signingkeys.Manager
		own string
	}{"a": {ma, ta}, "b": {mb, tb}} {
		set, err := tc.m.LoadKeys(ctx)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(set.Keys) != 2 || !hasKey(set, ta) || !hasKey(set, tb) || hasKey(set, pki.Thumbprint(selfSigned.Raw)) {
			t.Fatalf("%s: keys = %v", name, kids(set))
		}
		if set.Active.KID != tc.own || set.Signer == nil {
			t.Fatalf("%s: active %q, want %q (signer %v)", name, set.Active.KID, tc.own, set.Signer)
		}
		for _, k := range set.Keys {
			if len(k.Chain) != 2 || k.Algorithm != "EdDSA" || k.NotAfter.IsZero() {
				t.Fatalf("%s: key %+v", name, k)
			}
		}
	}
}

// The manager's set passes the issuer's validation, and a token it signs
// verifies against the same set.
func TestLoadKeysSetIsAValidKeySet(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	m := e.newManager(t)
	iss, err := token.NewIssuer(ctx, "http://localhost:8420", m, time.Hour, e.clk.now)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	raw, _, err := iss.Mint(ctx, token.MintInput{Identity: "alice", Kind: token.KindAgent})
	if err != nil {
		t.Fatal(err)
	}
	if sub, err := iss.Verify(ctx, raw, e.clk.now()); err != nil || sub != "alice" {
		t.Fatalf("Verify = %q, %v", sub, err)
	}
}

func TestLoadKeysActiveIsEmptyWhenTheLeafCannotSign(t *testing.T) {
	ctx := context.Background()
	t.Run("expired", func(t *testing.T) {
		e := newEnv(t)
		e.f.Install(t, e.c)
		m := e.newManager(t)
		e.clk.advance(week + 2*token.Leeway)
		if tp, _ := m.Current(); tp != "" {
			t.Fatalf("Current = %q for an expired leaf", tp)
		}
		set, err := m.LoadKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if set.Signer != nil || set.Active.KID != "" || len(set.Keys) != 0 {
			t.Fatalf("set = %+v, want nothing that signs and no keys", set)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		e := newEnv(t)
		e.f.Install(t, e.c)
		m := e.newManager(t)
		leaf, err := x509.ParseCertificate(e.leafRows(t)[0].DER)
		if err != nil {
			t.Fatal(err)
		}
		e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate),
			crlBy(t, e.f.Intermediate, interKey(t, e.f), 5, e.clk.now(), leaf.SerialNumber))
		set, err := m.LoadKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if set.Signer != nil || set.Active.KID != "" || len(set.Keys) != 0 {
			t.Fatalf("set = %+v, want a revoked leaf neither published nor active", set)
		}
		if tp, _ := m.Current(); tp != "" {
			t.Fatalf("Current = %q for a revoked leaf", tp)
		}
	})
}

func TestFailedInsertLeavesTheLeafUnused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	fs := &leafFailStore{Store: e.st}
	tr := e.f.Trust(e.coreOver(t, fs))

	fs.setFailLeaf(true)
	if _, err := signingkeys.New(ctx, signingkeys.Options{Trust: tr, LeafValidity: week}); err == nil {
		t.Fatal("New succeeded with a failing insert")
	}
	if n := len(e.leafRows(t)); n != 0 {
		t.Fatalf("%d leaf rows after a failed start", n)
	}

	fs.setFailLeaf(false)
	m, err := signingkeys.New(ctx, signingkeys.Options{Trust: tr, LeafValidity: week})
	if err != nil {
		t.Fatal(err)
	}
	tp, na := m.Current()
	fs.setFailLeaf(true)
	e.clk.advance(time.Minute)
	if err := m.Issue(ctx); err == nil {
		t.Fatal("Issue succeeded with a failing insert")
	}
	if tp2, na2 := m.Current(); tp2 != tp || !na2.Equal(na) {
		t.Fatalf("Current moved from %q to %q", tp, tp2)
	}
	if n := len(e.leafRows(t)); n != 1 {
		t.Fatalf("%d leaf rows, want 1", n)
	}
}

func TestNoPrivateKeyInTheStore(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	m := e.newManager(t)
	e.clk.advance(time.Minute)
	if err := m.Issue(ctx); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(e.leafRows(t)[0].DER)
	if err != nil {
		t.Fatal(err)
	}
	e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate),
		crlBy(t, e.f.Intermediate, interKey(t, e.f), 3, e.clk.now(), leaf.SerialNumber))

	db, err := sql.Open("sqlite", "file:"+e.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT kind, der FROM trust_material WHERE kind != 'trust_number'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var kind string
		var der []byte
		if err := rows.Scan(&kind, &der); err != nil {
			t.Fatal(err)
		}
		_, cerr := x509.ParseCertificate(der)
		_, rerr := x509.ParseRevocationList(der)
		if cerr != nil && rerr != nil {
			t.Fatalf("a %s row is neither a certificate nor a CRL", kind)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 4 { // the intermediate, two leaves and the leaf CRL
		t.Fatalf("%d rows scanned, want 4", n)
	}
}

// fixedSource serves one key set, so token.NewIssuer validates it.
type fixedSource struct{ set token.KeySet }

func (f fixedSource) LoadKeys(context.Context) (token.KeySet, error) { return f.set, nil }

func TestManagerConcurrentUse(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	m := e.newManager(t)
	var (
		wg   sync.WaitGroup
		stop atomic.Bool
		errs = make(chan error, 64)
	)
	fail := func(err error) {
		select {
		case errs <- err:
		default:
		}
	}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				set, err := m.LoadKeys(ctx)
				if err != nil {
					fail(err)
					return
				}
				m.Current()
				// The leaf is always valid here, so every set has a signer, an
				// active key among its keys and passes the issuer's validation.
				if set.Signer == nil || set.Active.KID == "" || !hasKey(set, set.Active.KID) {
					fail(errors.New("a set has no signer or its active key is not among its keys"))
					return
				}
				for _, k := range set.Keys {
					if len(k.Chain) != 2 || k.KID != pki.Thumbprint(k.Chain[0]) {
						fail(errors.New("a published key does not match its chain"))
						return
					}
				}
				if _, err := token.NewIssuer(ctx, "http://localhost:8420", fixedSource{set}, time.Hour, e.clk.now); err != nil {
					fail(err)
					return
				}
			}
		}()
	}
	for range 40 {
		e.clk.advance(time.Millisecond)
		if err := m.Issue(ctx); err != nil {
			t.Fatalf("Issue: %v", err)
		}
	}
	stop.Store(true)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	set, err := m.LoadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 41 {
		t.Fatalf("%d keys, want 41", len(set.Keys))
	}
}

// waitProvider wraps the file provider; once armed, every signature waits on
// release.
type waitProvider struct {
	keyprovider.Provider
	armed   atomic.Bool
	reached atomic.Int32 // signatures that began while armed
	waiting chan struct{}
	release chan struct{}
}

func (p *waitProvider) Signer(ctx context.Context, k keyprovider.Key) (keyprovider.Signer, error) {
	s, err := p.Provider.Signer(ctx, k)
	return waitSigner{Signer: s, p: p}, err
}

type waitSigner struct {
	keyprovider.Signer
	p *waitProvider
}

func (s waitSigner) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.p.armed.Load() {
		s.p.reached.Add(1)
		select {
		case s.p.waiting <- struct{}{}:
		default:
		}
		select {
		case <-s.p.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.Signer.SignContext(ctx, digest, opts)
}

func TestLoadKeysNotBlockedBySigning(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	wp := &waitProvider{Provider: e.tr.Provider, waiting: make(chan struct{}, 1), release: make(chan struct{})}
	tr := e.tr
	tr.Provider = wp
	m, err := signingkeys.New(ctx, signingkeys.Options{Trust: tr, LeafValidity: week})
	if err != nil {
		t.Fatal(err)
	}
	wp.armed.Store(true)
	done := make(chan error, 1)
	go func() { done <- m.Issue(ctx) }()
	select {
	case <-wp.waiting:
	case <-time.After(10 * time.Second):
		t.Fatal("the issue never reached the signature")
	}
	loaded := make(chan error, 1)
	go func() {
		_, err := m.LoadKeys(ctx)
		if err == nil {
			m.Current()
		}
		loaded <- err
	}()
	select {
	case err := <-loaded:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LoadKeys was blocked by a leaf waiting for its signature")
	}
	close(wp.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Two issues in one process never overlap: the second waits on issueMu until
// the first is done, so it does not reach the signature while the first waits.
func TestConcurrentIssuesDoNotOverlap(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	wp := &waitProvider{Provider: e.tr.Provider, waiting: make(chan struct{}, 1), release: make(chan struct{})}
	tr := e.tr
	tr.Provider = wp
	m, err := signingkeys.New(ctx, signingkeys.Options{Trust: tr, LeafValidity: week})
	if err != nil {
		t.Fatal(err)
	}
	wp.armed.Store(true)
	done := make(chan error, 2)
	go func() { done <- m.Issue(ctx) }()
	select {
	case <-wp.waiting:
	case <-time.After(10 * time.Second):
		t.Fatal("the first issue never reached the signature")
	}
	go func() { done <- m.Issue(ctx) }()
	time.Sleep(300 * time.Millisecond)
	if n := wp.reached.Load(); n != 1 {
		t.Fatalf("%d signatures began while the first issue waited, want 1", n)
	}
	close(wp.release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if n := wp.reached.Load(); n != 2 {
		t.Fatalf("%d signatures, want 2", n)
	}
	if n := len(e.leafRows(t)); n != 3 {
		t.Fatalf("%d leaf rows, want 3", n)
	}
}

// Current follows the last load: a leaf that the last load no longer verifies
// is not current, as LoadKeys's Active says.
func TestCurrentFollowsTheLastLoad(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	m := e.newManager(t)
	if tp, _ := m.Current(); tp == "" {
		t.Fatal("no current leaf after the start")
	}
	var ids []int64
	for _, r := range e.leafRows(t) {
		ids = append(ids, r.ID)
	}
	e.tx(t, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.DeleteTrustCertificates(ctx, ids)
		return err
	})
	set, err := m.LoadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if set.Signer != nil || set.Active.KID != "" {
		t.Fatalf("set = %+v, want no signer", set)
	}
	if tp, _ := m.Current(); tp != "" {
		t.Fatalf("Current = %q after the load dropped the leaf", tp)
	}
}

// A signer is present in the set up to Leeway after the leaf's "not after";
// the issuer refuses to mint with it.
func TestLoadKeysWithinLeewayAfterNotAfter(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	m := e.newManager(t)
	e.clk.advance(week + token.Leeway/2)
	set, err := m.LoadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if set.Signer == nil || len(set.Keys) != 1 {
		t.Fatalf("set = %+v, want the leaf kept within the leeway", set)
	}
	iss, err := token.NewIssuer(ctx, "http://localhost:8420", m, time.Hour, e.clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := iss.Mint(ctx, token.MintInput{Identity: "alice", Kind: token.KindAgent}); err == nil {
		t.Fatal("Mint signed with a leaf past its not-after")
	}
}

func TestNewStoreFailureAtTheInitialReload(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	tr := e.f.Trust(e.coreOver(t, failingStore{Store: e.st, read: true}))
	_, err := signingkeys.New(context.Background(), signingkeys.Options{Trust: tr, LeafValidity: week})
	wantUnavailable(t, err)
	if n := len(e.leafRows(t)); n != 0 {
		t.Fatalf("%d leaf rows after a failed start", n)
	}
}

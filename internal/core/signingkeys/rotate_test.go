package signingkeys_test

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core/identities"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

// hookProvider wraps a provider and calls onSigner with the 1-based count of
// Signer calls since the last reset.
type hookProvider struct {
	keyprovider.Provider
	n        atomic.Int32
	onSigner func(n int)
}

func (p *hookProvider) Signer(ctx context.Context, k keyprovider.Key) (keyprovider.Signer, error) {
	n := int(p.n.Add(1))
	if p.onSigner != nil {
		p.onSigner(n)
	}
	return p.Provider.Signer(ctx, k)
}

// lockSpy counts TryLock calls.
type lockSpy struct {
	store.Store
	tries atomic.Int32
}

func (s *lockSpy) TryLock(ctx context.Context, name, owner string, now, until int64) (bool, error) {
	s.tries.Add(1)
	return s.Store.TryLock(ctx, name, owner, now, until)
}

// rotEnv is an installed environment with an administrator "root" and one
// manager.
func rotEnv(t *testing.T) (*env, *signingkeys.Manager) {
	t.Helper()
	e := newEnv(t)
	e.f.Install(t, e.c)
	e.admin(t, "root")
	return e, e.newManager(t)
}

// snapshot is what a failed or refused rotation must leave alone.
type snapshot struct {
	leaves int
	crl    string
	number int64
}

func (e *env) snap(t *testing.T) snapshot {
	t.Helper()
	row, _, _ := e.leafCRL(t)
	return snapshot{leaves: len(e.leafRows(t)), crl: row.Thumbprint, number: e.trustNumber(t)}
}

func (e *env) wantSnap(t *testing.T, want snapshot) {
	t.Helper()
	if got := e.snap(t); got != want {
		t.Fatalf("state changed: %+v, want %+v", got, want)
	}
}

func rotate(ctx context.Context, m *signingkeys.Manager, key string) (bus.SigningKeyRotation, error) {
	return m.RotateSigningKey(ctx, "root", bus.RotateSigningKeyInput{IdempotencyKey: key})
}

func TestRotateRevokesEveryOtherLeaf(t *testing.T) {
	ctx := context.Background()
	e, m1 := rotEnv(t)
	m2 := e.managerOn(t, e.coreOver(t, e.st))
	m3 := e.managerOn(t, e.coreOver(t, e.st))
	e.clk.advance(84 * time.Hour)
	m1.Step(ctx) // m1 renews once
	certs := e.leafCerts(t)
	if len(certs) != 4 {
		t.Fatalf("%d leaf rows, want 4", len(certs))
	}
	oldTP, _ := m1.Current()
	before := e.trustNumber(t)

	res, err := rotate(ctx, m1, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Revoked) != 4 {
		t.Fatalf("revoked %d leaves, want 4: %v", len(res.Revoked), res.Revoked)
	}
	got := thumbs(res.Revoked)
	for _, c := range certs {
		if !got[pki.Thumbprint(c.Raw)] {
			t.Fatalf("leaf %s not revoked", pki.Thumbprint(c.Raw))
		}
	}
	for _, r := range res.Revoked {
		if r.HumanMessages != 0 {
			t.Fatalf("HumanMessages = %d", r.HumanMessages)
		}
	}
	if !got[oldTP] {
		t.Fatal("the caller's own former leaf was not revoked")
	}
	if want := pki.NextNumber(e.clk.now(), before); res.TrustNumber != want || e.trustNumber(t) != want {
		t.Fatalf("trust number %d / stored %d, want %d", res.TrustNumber, e.trustNumber(t), want)
	}
	row, crl, ok := e.leafCRL(t)
	if !ok {
		t.Fatal("no CRL")
	}
	set := crlSet(crl)
	if len(set) != 4 {
		t.Fatalf("CRL lists %d serial numbers, want 4", len(set))
	}
	for _, c := range certs {
		if !set[pki.SerialText(c.SerialNumber)] {
			t.Fatalf("serial %s not on the CRL", pki.SerialText(c.SerialNumber))
		}
	}
	if row.Number != pki.NextNumber(e.clk.now(), 0) {
		t.Fatalf("CRL number %d", row.Number)
	}
	if res.Current.State != bus.SigningKeyCurrent || res.Current.Thumbprint == "" || res.Current.Serial == "" ||
		res.Current.IssuerThumbprint != pki.Thumbprint(e.f.Intermediate.Raw) {
		t.Fatalf("Current = %+v", res.Current)
	}
	if set[res.Current.Serial] || len(e.leafRows(t)) != 5 {
		t.Fatal("the new leaf is on the CRL or has no row")
	}

	// The caller signs with the new leaf.
	tp, _ := m1.Current()
	if tp != res.Current.Thumbprint {
		t.Fatalf("Current = %q, want %q", tp, res.Current.Thumbprint)
	}
	keys, err := m1.LoadKeys(ctx)
	if err != nil || keys.Active.KID != tp || keys.Signer == nil || len(keys.Keys) != 1 {
		t.Fatalf("key set: active %q keys %v, %v", keys.Active.KID, kids(keys), err)
	}

	// The others issue new leaves at the Step after their next Reload.
	for i, m := range []*signingkeys.Manager{m2, m3} {
		prev, _ := m.Current()
		if err := m.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		wantWake(t, m, true)
		if cur, _ := m.Current(); cur != "" {
			t.Fatalf("manager %d still signs with %q", i+2, cur)
		}
		m.Step(ctx)
		if cur, _ := m.Current(); cur == "" || cur == prev {
			t.Fatalf("manager %d: Current = %q after the Step", i+2, cur)
		}
	}
}

func TestRotateReplay(t *testing.T) {
	ctx := context.Background()
	e, m := rotEnv(t)
	first, err := rotate(ctx, m, "same")
	if err != nil {
		t.Fatal(err)
	}
	s := e.snap(t)
	e.clk.advance(time.Minute)
	again, err := rotate(ctx, m, "same")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, again) {
		t.Fatalf("replay = %+v, first = %+v", again, first)
	}
	e.wantSnap(t, s)
	if tp, _ := m.Current(); tp != first.Current.Thumbprint {
		t.Fatal("the replay changed the current leaf")
	}
}

func TestRotateAgainWithoutKey(t *testing.T) {
	ctx := context.Background()
	e, m := rotEnv(t)
	first, err := rotate(ctx, m, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := rotate(ctx, m, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Revoked) != 1 || second.Revoked[0].Thumbprint != first.Current.Thumbprint {
		t.Fatalf("second rotation revoked %v, want the first rotation's leaf", second.Revoked)
	}
	if second.Current.Thumbprint == first.Current.Thumbprint || len(e.leafRows(t)) != 3 {
		t.Fatalf("second rotation: %+v, %d rows", second.Current, len(e.leafRows(t)))
	}
	if second.TrustNumber <= first.TrustNumber {
		t.Fatalf("trust numbers %d then %d", first.TrustNumber, second.TrustNumber)
	}
}

func TestRotateNonAdminRefused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	spy := &lockSpy{Store: e.st}
	m := e.managerOn(t, e.coreOver(t, spy))
	if err := (identities.Service{Core: e.c}).RegisterLocal(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	s := e.snap(t)
	for _, who := range []string{"bob", ""} {
		_, err := m.RotateSigningKey(ctx, who, bus.RotateSigningKeyInput{IdempotencyKey: "x"})
		if who == "bob" && bus.CodeOf(err) != bus.CodeForbidden {
			t.Fatalf("bob: %v", err)
		}
		if err == nil {
			t.Fatalf("%q was accepted", who)
		}
	}
	if spy.tries.Load() != 0 {
		t.Fatal("the trust lock was taken for a refused caller")
	}
	e.wantSnap(t, s)
}

func TestRotateLockHeld(t *testing.T) {
	ctx := context.Background()
	e, m := rotEnv(t)
	now := e.nowMs()
	if held, err := e.st.TryLock(ctx, signingkeys.LockName, "someone-else", now, now+signingkeys.LockTTL.Milliseconds()); err != nil || !held {
		t.Fatalf("setup: %v %v", held, err)
	}
	s := e.snap(t)
	_, err := rotate(ctx, m, "k")
	wantUnavailable(t, err)
	e.wantSnap(t, s)
}

func TestRotateTwoAtOnce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	e.admin(t, "root")
	gate := &hookProvider{Provider: e.tr.Provider}
	tr1 := e.tr
	tr1.Provider = gate
	m1, err := signingkeys.New(ctx, signingkeys.Options{Trust: tr1, LeafValidity: week})
	if err != nil {
		t.Fatal(err)
	}
	m2 := e.managerOn(t, e.coreOver(t, e.st))
	gate.n.Store(0)
	entered, release := make(chan struct{}), make(chan struct{})
	gate.onSigner = func(n int) {
		if n == 1 {
			close(entered)
			<-release
		}
	}
	type result struct {
		r   bus.SigningKeyRotation
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := rotate(ctx, m1, "one")
		done <- result{r, err}
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first rotation never reached the key")
	}
	s := e.snap(t)
	_, err = rotate(ctx, m2, "two")
	wantUnavailable(t, err)
	e.wantSnap(t, s)
	close(release)
	var first result
	select {
	case first = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the first rotation did not finish")
	}
	if first.err != nil {
		t.Fatal(first.err)
	}
	second, err := rotate(ctx, m2, "two")
	if err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if !thumbs(second.Revoked)[first.r.Current.Thumbprint] {
		t.Fatal("the second rotation did not revoke the first one's leaf")
	}
}

func TestRotateNumberAfterRestore(t *testing.T) {
	ctx := context.Background()
	e, m := rotEnv(t)
	ahead := int64(startMs) + 10_000_000
	e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate), crlBy(t, e.f.Intermediate, interKey(t, e.f), ahead, e.clk.now()))
	if _, err := rotate(ctx, m, "k"); err != nil {
		t.Fatal(err)
	}
	row, _, _ := e.leafCRL(t)
	if row.Number != ahead+1 {
		t.Fatalf("CRL number %d, want %d", row.Number, ahead+1)
	}
}

func TestRotateCarriesTheUnion(t *testing.T) {
	ctx := context.Background()
	e, m := rotEnv(t)
	kept := big.NewInt(777001)
	e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate), crlBy(t, e.f.Intermediate, interKey(t, e.f), 5, e.clk.now(), kept))
	if err := m.Reload(ctx); err != nil { // the manager's memory now holds the serial number
		t.Fatal(err)
	}
	// Another process reissues the CRL without it.
	e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate), crlBy(t, e.f.Intermediate, interKey(t, e.f), 6, e.clk.now(), big.NewInt(1)))
	if _, err := rotate(ctx, m, "k"); err != nil {
		t.Fatal(err)
	}
	_, crl, _ := e.leafCRL(t)
	set := crlSet(crl)
	if !set[pki.SerialText(kept)] || !set["1"] {
		t.Fatalf("CRL entries %v: want the serial number the manager's memory held and the stored one", set)
	}
}

func TestRotateKeepsEntries(t *testing.T) {
	ctx := context.Background()
	e, m := rotEnv(t)
	old := leafFor(t, e.f, e.clk.now(), week)
	e.putLeaf(t, old, keyID(e.f.Intermediate))
	e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate), crlBy(t, e.f.Intermediate, interKey(t, e.f), 5, e.clk.now(), old.SerialNumber))
	var ids []int64
	for _, r := range e.leafRows(t) {
		if r.Thumbprint == pki.Thumbprint(old.Raw) {
			ids = append(ids, r.ID)
		}
	}
	e.tx(t, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.DeleteTrustCertificates(ctx, ids)
		return err
	})
	if _, err := rotate(ctx, m, "k"); err != nil {
		t.Fatal(err)
	}
	_, crl, _ := e.leafCRL(t)
	if !crlSet(crl)[pki.SerialText(old.SerialNumber)] {
		t.Fatal("the entry of a leaf whose row is gone left the CRL")
	}
}

func TestRotateFailsBeforeTheTransaction(t *testing.T) {
	ctx := context.Background()
	e, _, p := renewEnv(t)
	e.admin(t, "root")
	tr := e.tr
	tr.Provider = p
	m, err := signingkeys.New(ctx, signingkeys.Options{Trust: tr, LeafValidity: week})
	if err != nil {
		t.Fatal(err)
	}
	s := e.snap(t)
	p.down.Store(true)
	_, err = rotate(ctx, m, "k")
	wantUnavailable(t, err)
	e.wantSnap(t, s)

	// The retry with the same key runs again: no receipt was stored.
	p.down.Store(false)
	res, err := rotate(ctx, m, "k")
	if err != nil || res.Current.Thumbprint == "" {
		t.Fatalf("retry: %+v, %v", res, err)
	}
	if got := e.snap(t); got.leaves != s.leaves+1 {
		t.Fatalf("leaf rows %d, want %d", got.leaves, s.leaves+1)
	}
}

func TestRotateNotCovered(t *testing.T) {
	ctx := context.Background()
	e, m := rotEnv(t)
	foreign := e.otherKeyLeaf(t)
	res, err := rotate(ctx, m, "k")
	if err != nil {
		t.Fatal(err)
	}
	if thumbs(res.Revoked)[pki.Thumbprint(foreign.Raw)] {
		t.Fatal("a leaf under another key was reported revoked")
	}
	_, crl, _ := e.leafCRL(t)
	if crlSet(crl)[pki.SerialText(foreign.SerialNumber)] {
		t.Fatal("a leaf under another key is on the CRL")
	}
	if !e.logged(pki.Thumbprint(foreign.Raw)) || !e.logged("not covered") {
		t.Fatalf("the uncovered leaf was not logged:\n%s", e.logs.String())
	}
}

func TestRotateRenewsTheLease(t *testing.T) {
	for _, steal := range []bool{false, true} {
		t.Run(fmt.Sprintf("another owner takes it: %v", steal), func(t *testing.T) {
			ctx := context.Background()
			e := newEnv(t)
			e.f.Install(t, e.c)
			e.admin(t, "root")
			hp := &hookProvider{Provider: e.tr.Provider}
			tr := e.tr
			tr.Provider = hp
			m, err := signingkeys.New(ctx, signingkeys.Options{Trust: tr, LeafValidity: week})
			if err != nil {
				t.Fatal(err)
			}
			hp.n.Store(0)
			other := openAt(t, e.path)
			hp.onSigner = func(n int) {
				if n != 2 { // the second use of the key signs the CRL
					return
				}
				e.clk.advance(signingkeys.LockTTL + time.Second)
				if steal {
					now := e.nowMs()
					if held, err := other.TryLock(ctx, signingkeys.LockName, "thief", now, now+signingkeys.LockTTL.Milliseconds()); err != nil || !held {
						t.Errorf("the thief did not get the lock: %v %v", held, err)
					}
				}
			}
			s := e.snap(t)
			res, err := rotate(ctx, m, "k")
			if steal {
				wantUnavailable(t, err)
				e.wantSnap(t, s)
				return
			}
			if err != nil || res.Current.Thumbprint == "" {
				t.Fatalf("rotation: %+v, %v", res, err)
			}
			if got := e.snap(t); got.leaves != s.leaves+1 || got.crl == s.crl {
				t.Fatalf("state %+v from %+v", got, s)
			}
		})
	}
}

func TestRotateWhenOwnLeafRevoked(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	e.admin(t, "root")
	old, serial := e.onlyLeaf(t)
	e.revokeLeaf(t, 5, serial) // the host form listed the leaf; the manager has not reloaded
	type result struct {
		r   bus.SigningKeyRotation
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := rotate(ctx, m, "k")
		done <- result{r, err}
	}()
	var res result
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the rotation did not finish within 10 seconds")
	}
	if res.err != nil {
		t.Fatal(res.err)
	}
	tp, _ := m.Current()
	if tp == "" || tp == old || tp != res.r.Current.Thumbprint {
		t.Fatalf("Current = %q, rotation answered %q (old %q)", tp, res.r.Current.Thumbprint, old)
	}
	if rows := e.leafRows(t); len(rows) != 2 {
		t.Fatalf("%d leaf rows, want the old one and the new one (the reload issued nothing)", len(rows))
	}
	if p.calls.Load() != 2 {
		t.Fatalf("%d uses of the key, want 2 (the new leaf and the CRL)", p.calls.Load())
	}
	if len(res.r.Revoked) != 0 {
		t.Fatalf("revoked %v, but the host form had listed the only leaf already", res.r.Revoked)
	}
}

// OnChange runs inside the rotation while the manager's locks are held; a
// callback that reads the manager does not deadlock.
func TestRotateOnChangeReadsTheManager(t *testing.T) {
	ctx := context.Background()
	e, m := rotEnv(t)
	other := e.managerOn(t, e.coreOver(t, e.st))
	_ = other
	var calls atomic.Int32
	m.SetOnChange(func() {
		calls.Add(1)
		m.Current()
		if _, err := m.LoadKeys(ctx); err != nil {
			t.Errorf("LoadKeys in OnChange: %v", err)
		}
	})
	done := make(chan error, 1)
	go func() { _, err := rotate(ctx, m, "k"); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock: the rotation did not finish")
	}
	if calls.Load() == 0 {
		t.Fatal("OnChange never ran")
	}
}

// A leaf row whose chain does not verify is ignored by Load and never revoked.
func TestRotateIgnoresUnverifiedRows(t *testing.T) {
	ctx := context.Background()
	e, m := rotEnv(t)
	bad := overlongLeaf(t, e.f, e.clk.now(), 90*24*time.Hour)
	e.putRow(t, storeLeafRow(bad, bad.Raw, keyID(e.f.Intermediate)))
	res, err := rotate(ctx, m, "k")
	if err != nil {
		t.Fatal(err)
	}
	if thumbs(res.Revoked)[pki.Thumbprint(bad.Raw)] || len(res.Revoked) != 1 {
		t.Fatalf("revoked %v", res.Revoked)
	}
	if !strings.Contains(e.logs.String(), "ignored") {
		t.Fatal("the unverifiable row was not logged")
	}
}

func wantUnavailableFinal(t *testing.T, err error) *bus.Error {
	t.Helper()
	var be *bus.Error
	if !errors.As(err, &be) || be.Code != bus.CodeUnavailable {
		t.Fatalf("err = %v, want an unavailable", err)
	}
	return be
}

// No failure of the signing steps is a 500: each maps to an unavailable, and
// only an outage or a timeout is retryable.
func TestRotateErrorMapping(t *testing.T) {
	ctx := context.Background()
	t.Run("stopped: intermediate revoked", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		e.admin(t, "root")
		if _, err := e.tr.InstallRootCRL(ctx, e.f.RevokeIntermediate(t, e.clk.now())); err != nil {
			t.Fatal(err)
		}
		s := e.snap(t)
		_, err := rotate(ctx, m, "k")
		if be := wantUnavailableFinal(t, err); be.Retryable {
			t.Fatal("a revoked intermediate is retryable")
		}
		e.wantSnap(t, s)
	})
	t.Run("stopped: intermediate expired", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		e.admin(t, "root")
		e.at(400 * 24 * time.Hour)
		_, err := rotate(ctx, m, "k")
		if be := wantUnavailableFinal(t, err); be.Retryable {
			t.Fatal("an expired intermediate is retryable")
		}
	})
	t.Run("outage", func(t *testing.T) {
		e, m, p := renewEnv(t)
		e.admin(t, "root")
		p.down.Store(true)
		_, err := rotate(ctx, m, "k")
		if be := wantUnavailableFinal(t, err); !be.Retryable {
			t.Fatal("an outage is not retryable")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		e, m, p := renewEnv(t)
		e.admin(t, "root")
		p.err = fmt.Errorf("sign: %w", context.DeadlineExceeded)
		p.down.Store(true)
		_, err := rotate(ctx, m, "k")
		if be := wantUnavailableFinal(t, err); !be.Retryable {
			t.Fatal("a timeout is not retryable")
		}
	})
	t.Run("any other key failure", func(t *testing.T) {
		e, m, p := renewEnv(t)
		e.admin(t, "root")
		p.err = errors.New("the key file is unreadable")
		p.down.Store(true)
		s := e.snap(t)
		_, err := rotate(ctx, m, "k")
		be := wantUnavailableFinal(t, err)
		if be.Retryable || !strings.Contains(be.Error(), "the key file is unreadable") {
			t.Fatalf("err = %v, want a non-retryable unavailable naming the cause", err)
		}
		e.wantSnap(t, s)
	})
}

// The process holds a leaf CRL newer than the stored one (a rolled-back
// database): the rotation numbers from the held one and keeps its entries.
func TestRotateNumbersFromTheHeldCRL(t *testing.T) {
	ctx := context.Background()
	e, m, _ := renewEnv(t)
	e.admin(t, "root")
	held := int64(startMs) + 10_000_000
	e.revokeLeaf(t, held, big.NewInt(99))
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	older := crlBy(t, e.f.Intermediate, interKey(t, e.f), 3000, e.clk.now())
	if _, err := rawDB(t, e).Exec("UPDATE trust_material SET thumbprint = ?, der = ?, number = 3000 WHERE kind = 'leaf_crl'",
		pki.Thumbprint(older), older); err != nil {
		t.Fatal(err)
	}
	if _, err := rotate(ctx, m, "k"); err != nil {
		t.Fatal(err)
	}
	row, crl, _ := e.leafCRL(t)
	if row.Number != held+1 {
		t.Fatalf("CRL number %d, want %d (the held one plus one)", row.Number, held+1)
	}
	if !crlSet(crl)["63"] {
		t.Fatalf("the held CRL's entry is gone: %v", crlSet(crl))
	}
	if e.logged("held elsewhere") || !e.logged("by the operation that is reloading") {
		t.Fatalf("the write-back log is misleading:\n%s", e.logs.String())
	}
}

// A leaf of another key that is revoked already needs no "not covered" line.
func TestRotateNotCoveredSkipsRevoked(t *testing.T) {
	ctx := context.Background()
	e, m := rotEnv(t)
	k2 := newP256(t)
	inter2 := craft(t, e.f, &k2.PublicKey, nil)
	e.putIntermediate(t, inter2, "")
	leaf := leafUnder(t, inter2, k2, e.clk.now(), week)
	e.putLeaf(t, leaf, keyID(inter2))
	e.putCRL(t, store.TrustLeafCRL, keyID(inter2), crlBy(t, inter2, k2, 5, e.clk.now(), leaf.SerialNumber))
	if _, err := rotate(ctx, m, "k"); err != nil {
		t.Fatal(err)
	}
	if e.logged(pki.Thumbprint(leaf.Raw)) {
		t.Fatalf("a revoked leaf of another key was logged as not covered:\n%s", e.logs.String())
	}
}

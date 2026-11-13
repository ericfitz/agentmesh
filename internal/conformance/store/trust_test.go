package store

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/ericfitz/agentmesh/internal/dbtest"
	ab2store "github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/store/sqlstore"
)

func trustIntermediate(thumb string) ab2store.TrustCertificate {
	return ab2store.TrustCertificate{Kind: ab2store.TrustIntermediate, Thumbprint: thumb, DER: []byte{1, 2, thumb[0]},
		NotAfter: fixedNow + 1000, KeyRef: "ref-" + thumb, CreatedAt: fixedNow}
}

func trustLeaf(thumb, issuer string, notAfter int64) ab2store.TrustCertificate {
	return ab2store.TrustCertificate{Kind: ab2store.TrustLeaf, Thumbprint: thumb, DER: []byte{3, 4, thumb[0]},
		IssuerKey: issuer, NotAfter: notAfter, CreatedAt: fixedNow}
}

func putTrust(t *testing.T, s ab2store.Store, cs ...ab2store.TrustCertificate) []int64 {
	t.Helper()
	var ids []int64
	mustTx(t, s, func(ctx context.Context, tx ab2store.Tx) error {
		for _, c := range cs {
			id, err := tx.PutTrustCertificate(ctx, c)
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})
	return ids
}

func trustCerts(t *testing.T, s ab2store.Store, kind string) []ab2store.TrustCertificate {
	t.Helper()
	var got []ab2store.TrustCertificate
	mustRead(t, s, func(ctx context.Context, tx ab2store.Tx) (err error) {
		got, err = tx.TrustCertificates(ctx, kind)
		return err
	})
	return got
}

func TestTrustCertificates(t *testing.T) {
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		s, _, _ := openStore(t, e, sqlstore.Options{})
		if got := trustCerts(t, s, ab2store.TrustLeaf); got == nil || len(got) != 0 {
			t.Fatalf("empty store lists %#v, want empty non-nil", got)
		}
		ids := putTrust(t, s, trustIntermediate("a"), trustLeaf("b", "k1", fixedNow+5), trustLeaf("c", "k1", fixedNow+6))
		if ids[0] >= ids[1] || ids[1] >= ids[2] {
			t.Fatalf("ids %v do not grow", ids)
		}
		leaves := trustCerts(t, s, ab2store.TrustLeaf)
		if len(leaves) != 2 || leaves[0].Thumbprint != "b" || leaves[1].Thumbprint != "c" || leaves[0].ID != ids[1] {
			t.Fatalf("leaves = %+v", leaves)
		}
		want := trustIntermediate("a")
		want.ID = ids[0]
		if got := trustCerts(t, s, ab2store.TrustIntermediate); !reflect.DeepEqual(got, []ab2store.TrustCertificate{want}) {
			t.Fatalf("intermediates = %+v, want %+v", got, want)
		}
		mustRead(t, s, func(ctx context.Context, tx ab2store.Tx) error {
			got, ok, err := tx.TrustCertificateByThumbprint(ctx, ab2store.TrustIntermediate, "a")
			if err != nil || !ok || !reflect.DeepEqual(got, want) {
				t.Errorf("by thumbprint = %+v, %v, %v", got, ok, err)
			}
			if _, ok, err := tx.TrustCertificateByThumbprint(ctx, ab2store.TrustLeaf, "a"); err != nil || ok {
				t.Errorf("a leaf lookup of an intermediate thumbprint = %v, %v", ok, err)
			}
			if _, ok, err := tx.TrustCertificateByThumbprint(ctx, ab2store.TrustLeaf, "bad\x00"); err != nil || ok {
				t.Errorf("bad text lookup = %v, %v", ok, err)
			}
			if _, _, err := tx.TrustCertificateByThumbprint(ctx, "root_crl", "a"); !errors.Is(err, ab2store.ErrInvalid) {
				t.Errorf("lookup of a CRL kind = %v, want ErrInvalid", err)
			}
			if _, err := tx.TrustCertificates(ctx, "trust_number"); !errors.Is(err, ab2store.ErrInvalid) {
				t.Errorf("list of trust_number = %v, want ErrInvalid", err)
			}
			return nil
		})

		// The same thumbprint under the other kind is a different row; the same kind conflicts.
		err := s.Tx(context.Background(), func(ctx context.Context, tx ab2store.Tx) error {
			_, err := tx.PutTrustCertificate(ctx, trustLeaf("b", "k2", fixedNow+9))
			return err
		})
		if !errors.Is(err, ab2store.ErrConflict) {
			t.Fatalf("duplicate = %v, want ErrConflict", err)
		}
		putTrust(t, s, trustLeaf("a", "k1", fixedNow+9)) // kind differs: allowed

		bad := map[string]ab2store.TrustCertificate{
			"kind":               {Kind: "root_crl", Thumbprint: "x", DER: []byte{1}, NotAfter: 1, CreatedAt: 1},
			"empty kind":         {Thumbprint: "x", DER: []byte{1}, NotAfter: 1, CreatedAt: 1},
			"empty thumbprint":   {Kind: ab2store.TrustIntermediate, DER: []byte{1}, NotAfter: 1, CreatedAt: 1},
			"empty DER":          {Kind: ab2store.TrustIntermediate, Thumbprint: "x", NotAfter: 1, CreatedAt: 1},
			"zero not after":     {Kind: ab2store.TrustIntermediate, Thumbprint: "x", DER: []byte{1}, CreatedAt: 1},
			"zero created at":    {Kind: ab2store.TrustIntermediate, Thumbprint: "x", DER: []byte{1}, NotAfter: 1},
			"intermediate issue": {Kind: ab2store.TrustIntermediate, Thumbprint: "x", DER: []byte{1}, NotAfter: 1, CreatedAt: 1, IssuerKey: "k"},
			"leaf no issuer":     {Kind: ab2store.TrustLeaf, Thumbprint: "x", DER: []byte{1}, NotAfter: 1, CreatedAt: 1},
			"leaf key ref":       {Kind: ab2store.TrustLeaf, Thumbprint: "x", DER: []byte{1}, NotAfter: 1, CreatedAt: 1, IssuerKey: "k", KeyRef: "r"},
			"bad text":           {Kind: ab2store.TrustIntermediate, Thumbprint: "x\x00", DER: []byte{1}, NotAfter: 1, CreatedAt: 1},
		}
		for name, c := range bad {
			err := s.Tx(context.Background(), func(ctx context.Context, tx ab2store.Tx) error {
				_, err := tx.PutTrustCertificate(ctx, c)
				return err
			})
			if !errors.Is(err, ab2store.ErrInvalid) {
				t.Errorf("%s: %v, want ErrInvalid", name, err)
			}
		}
		if err := s.Read(context.Background(), func(ctx context.Context, tx ab2store.Tx) error {
			_, err := tx.PutTrustCertificate(ctx, trustIntermediate("z"))
			return err
		}); !errors.Is(err, ab2store.ErrReadOnly) {
			t.Errorf("put in Read = %v, want ErrReadOnly", err)
		}
	})
}

func crl(kind, issuer string, number int64, tag byte) ab2store.TrustCRL {
	return ab2store.TrustCRL{Kind: kind, Thumbprint: "t" + string(rune('0'+number)), DER: []byte{9, tag}, IssuerKey: issuer, Number: number, CreatedAt: fixedNow}
}

func readCRLs(t *testing.T, s ab2store.Store) []ab2store.TrustCRL {
	t.Helper()
	var got []ab2store.TrustCRL
	mustRead(t, s, func(ctx context.Context, tx ab2store.Tx) (err error) {
		got, err = tx.CRLs(ctx)
		return err
	})
	return got
}

func TestPutCRL(t *testing.T) {
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		s, _, _ := openStore(t, e, sqlstore.Options{})
		put := func(c ab2store.TrustCRL) error {
			return s.Tx(context.Background(), func(ctx context.Context, tx ab2store.Tx) error { return tx.PutCRL(ctx, c) })
		}
		if got := readCRLs(t, s); got == nil || len(got) != 0 {
			t.Fatalf("empty store lists %#v", got)
		}
		leafB := crl(ab2store.TrustLeafCRL, "kb", 1, 1)
		leafA := crl(ab2store.TrustLeafCRL, "ka", 1, 2)
		root := crl(ab2store.TrustRootCRL, "", 1, 3)
		for _, c := range []ab2store.TrustCRL{leafB, leafA, root} {
			if err := put(c); err != nil {
				t.Fatal(err)
			}
		}
		if got := readCRLs(t, s); !reflect.DeepEqual(got, []ab2store.TrustCRL{root, leafA, leafB}) {
			t.Fatalf("CRLs = %+v, want root, ka, kb", got)
		}
		newer := crl(ab2store.TrustRootCRL, "", 2, 4)
		if err := put(newer); err != nil {
			t.Fatalf("higher number: %v", err)
		}
		for _, c := range []ab2store.TrustCRL{newer, crl(ab2store.TrustRootCRL, "", 1, 5)} { // equal, lower
			if err := put(c); !errors.Is(err, ab2store.ErrConflict) {
				t.Fatalf("number %d over 2 = %v, want ErrConflict", c.Number, err)
			}
		}
		if got := readCRLs(t, s); !reflect.DeepEqual(got, []ab2store.TrustCRL{newer, leafA, leafB}) {
			t.Fatalf("after conflicts CRLs = %+v", got)
		}
		bad := map[string]ab2store.TrustCRL{
			"kind":            {Kind: ab2store.TrustLeaf, Thumbprint: "t", DER: []byte{1}, IssuerKey: "k", Number: 1, CreatedAt: 1},
			"trust number":    {Kind: "trust_number", Thumbprint: "t", DER: []byte{1}, Number: 1, CreatedAt: 1},
			"no thumbprint":   {Kind: ab2store.TrustRootCRL, DER: []byte{1}, Number: 1, CreatedAt: 1},
			"no DER":          {Kind: ab2store.TrustRootCRL, Thumbprint: "t", Number: 1, CreatedAt: 1},
			"zero number":     {Kind: ab2store.TrustRootCRL, Thumbprint: "t", DER: []byte{1}, CreatedAt: 1},
			"negative number": {Kind: ab2store.TrustRootCRL, Thumbprint: "t", DER: []byte{1}, Number: -1, CreatedAt: 1},
			"zero created":    {Kind: ab2store.TrustRootCRL, Thumbprint: "t", DER: []byte{1}, Number: 1},
			"root with key":   {Kind: ab2store.TrustRootCRL, Thumbprint: "t", DER: []byte{1}, IssuerKey: "k", Number: 1, CreatedAt: 1},
			"leaf no key":     {Kind: ab2store.TrustLeafCRL, Thumbprint: "t", DER: []byte{1}, Number: 1, CreatedAt: 1},
		}
		for name, c := range bad {
			if err := put(c); !errors.Is(err, ab2store.ErrInvalid) {
				t.Errorf("%s: %v, want ErrInvalid", name, err)
			}
		}
	})
}

func bumpTrust(t *testing.T, s ab2store.Store, now int64) int64 {
	t.Helper()
	var n int64
	mustTx(t, s, func(ctx context.Context, tx ab2store.Tx) (err error) {
		n, err = tx.BumpTrustNumber(ctx, now)
		return err
	})
	return n
}

func TestTrustNumber(t *testing.T) {
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		s, reopen, _ := openStore(t, e, sqlstore.Options{})
		read := func(s ab2store.Store) (n int64) {
			mustRead(t, s, func(ctx context.Context, tx ab2store.Tx) (err error) {
				n, err = tx.TrustNumber(ctx)
				return err
			})
			return n
		}
		if got := read(s); got != 0 {
			t.Fatalf("new store reads %d, want 0", got)
		}
		if got := bumpTrust(t, s, 1000); got != 1000 {
			t.Fatalf("bump(1000) = %d", got)
		}
		if got := bumpTrust(t, s, 500); got != 1001 {
			t.Fatalf("bump(500) after 1000 = %d, want 1001 (clock set back)", got)
		}
		const big = 1767225600000 // above 1<<31
		if got := bumpTrust(t, s, big); got != big || read(s) != big {
			t.Fatalf("bump(%d) = %d, read %d", int64(big), got, read(s))
		}
		if err := s.Read(context.Background(), func(ctx context.Context, tx ab2store.Tx) error {
			_, err := tx.BumpTrustNumber(ctx, 1)
			return err
		}); !errors.Is(err, ab2store.ErrReadOnly) {
			t.Errorf("bump in Read = %v, want ErrReadOnly", err)
		}

		// A rolled back bump leaves the number alone.
		errBoom := errors.New("boom")
		if err := s.Tx(context.Background(), func(ctx context.Context, tx ab2store.Tx) error {
			if _, err := tx.BumpTrustNumber(ctx, big+100); err != nil {
				return err
			}
			return errBoom
		}); !errors.Is(err, errBoom) {
			t.Fatalf("rollback: %v", err)
		}
		if got := read(s); got != big {
			t.Fatalf("after rollback = %d, want %d", got, int64(big))
		}

		// Concurrent bumps from two handles never return the same number.
		s2, err := reopen(sqlstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s2.Close() })
		handles := []ab2store.Store{s, s2}
		const n = 8
		var wg sync.WaitGroup
		got := make([]int64, n)
		errs := make([]error, n)
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				// Postgres runs Tx at SERIALIZABLE with a bounded retry, so eight writers on one
				// row may exhaust it: a loser gets ErrRetryable and tries again.
				for range 20 {
					errs[i] = handles[i%2].Tx(context.Background(), func(ctx context.Context, tx ab2store.Tx) (err error) {
						got[i], err = tx.BumpTrustNumber(ctx, 1000)
						return err
					})
					if !errors.Is(errs[i], ab2store.ErrRetryable) {
						return
					}
				}
			}()
		}
		close(start)
		wg.Wait()
		seen := map[int64]bool{}
		for i := range n {
			if errs[i] != nil {
				t.Fatalf("bump %d: %v", i, errs[i])
			}
			if got[i] <= big || got[i] > big+n {
				t.Fatalf("number %d outside (%d, %d]: %v", got[i], int64(big), int64(big)+n, got)
			}
			if seen[got[i]] {
				t.Fatalf("number %d returned twice: %v", got[i], got)
			}
			seen[got[i]] = true
		}
		if final := read(s); final != big+n {
			t.Fatalf("final = %d, want %d", final, int64(big)+n)
		}
	})
}

func TestExpiredLeaves(t *testing.T) {
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		s, _, _ := openStore(t, e, sqlstore.Options{})
		old := trustIntermediate("i")
		old.NotAfter = 1 // an expired intermediate is never listed
		putTrust(t, s, old, trustLeaf("a", "k", 100), trustLeaf("b", "k", 200), trustLeaf("c", "k", 300), trustLeaf("d", "k", 400))
		list := func(before int64, limit int) (out []string) {
			mustRead(t, s, func(ctx context.Context, tx ab2store.Tx) error {
				cs, err := tx.ExpiredLeafCertificates(ctx, before, limit)
				for _, c := range cs {
					if c.Kind != ab2store.TrustLeaf {
						t.Errorf("listed a %s", c.Kind)
					}
					out = append(out, c.Thumbprint)
				}
				return err
			})
			return out
		}
		if got := list(300, 10); !reflect.DeepEqual(got, []string{"a", "b"}) { // strictly before
			t.Errorf("before 300 = %v", got)
		}
		if got := list(1000, 3); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
			t.Errorf("limit 3 = %v", got)
		}
		if got := list(100, 10); len(got) != 0 {
			t.Errorf("before 100 = %v", got)
		}
		if err := s.Read(context.Background(), func(ctx context.Context, tx ab2store.Tx) error {
			_, err := tx.ExpiredLeafCertificates(ctx, 1000, 0)
			return err
		}); !errors.Is(err, ab2store.ErrInvalid) {
			t.Errorf("limit 0 = %v, want ErrInvalid", err)
		}
	})
}

func TestDeleteTrustCertificates(t *testing.T) {
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		s, _, _ := openStore(t, e, sqlstore.Options{})
		ids := putTrust(t, s, trustIntermediate("i"), trustLeaf("a", "k", 100), trustLeaf("b", "k", 200), trustLeaf("c", "k", 300))
		del := func(ids ...int64) (n int, err error) {
			err = s.Tx(context.Background(), func(ctx context.Context, tx ab2store.Tx) (err error) {
				n, err = tx.DeleteTrustCertificates(ctx, ids)
				return err
			})
			return n, err
		}
		if _, err := del(ids[1], ids[0]); !errors.Is(err, ab2store.ErrInvalid) {
			t.Fatalf("with an intermediate id = %v, want ErrInvalid", err)
		}
		if len(trustCerts(t, s, ab2store.TrustLeaf)) != 3 || len(trustCerts(t, s, ab2store.TrustIntermediate)) != 1 {
			t.Fatal("a refused delete removed rows")
		}
		if n, err := del(ids[1], ids[2], 99999); err != nil || n != 2 {
			t.Fatalf("delete = %d, %v; want 2 (unknown id ignored)", n, err)
		}
		if n, err := del(ids[1], ids[2]); err != nil || n != 0 { // second run
			t.Fatalf("second delete = %d, %v; want 0", n, err)
		}
		if n, err := del(); err != nil || n != 0 {
			t.Fatalf("empty delete = %d, %v", n, err)
		}
		if got := trustCerts(t, s, ab2store.TrustLeaf); len(got) != 1 || got[0].Thumbprint != "c" {
			t.Fatalf("leaves = %+v", got)
		}
		many := make([]int64, 1200) // more than one chunk, all unknown
		for i := range many {
			many[i] = 100000 + int64(i)
		}
		if n, err := del(append(many, ids[3])...); err != nil || n != 1 {
			t.Fatalf("chunked delete = %d, %v; want 1", n, err)
		}
		if n, err := del(append(many, ids[0])...); !errors.Is(err, ab2store.ErrInvalid) || n != 0 {
			t.Fatalf("chunked with an intermediate = %d, %v", n, err)
		}
		if len(trustCerts(t, s, ab2store.TrustIntermediate)) != 1 {
			t.Fatal("intermediate gone")
		}
	})
}

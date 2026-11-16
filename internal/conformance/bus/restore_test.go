package bus

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/client"
	"github.com/ericfitz/agentmesh/internal/credential"
	"github.com/ericfitz/agentmesh/internal/dbtest"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/profile"
	"github.com/ericfitz/agentmesh/internal/server/cmd"
	"github.com/ericfitz/agentmesh/internal/testkit"
	"github.com/ericfitz/agentmesh/internal/trust"
)

// crlRow is the stored leaf CRL row, read and written through the suite's raw
// database handle.
type crlRow struct {
	thumbprint string
	der        []byte
	issuerKey  string
	number     int64
	createdAt  int64
}

// rawTrust is the raw database handle of TestRestore: the stored leaf CRL and
// the trust number as plain rows, so a test can put them back to older values
// (the Store refuses a lower CRL number, and nothing lowers the trust number).
type rawTrust struct {
	t      *testing.T
	db     *sql.DB
	engine string
}

func openRawTrust(t *testing.T, e dbtest.Engine, dsn string) *rawTrust {
	t.Helper()
	conn := dsn
	if e.Name == "sqlite" {
		conn = "file:" + dsn + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open(e.Driver, conn)
	if err != nil {
		t.Fatalf("raw handle: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &rawTrust{t: t, db: db, engine: e.Name}
}

// q turns ? placeholders into $n for Postgres.
func (r *rawTrust) q(s string) string {
	if r.engine != "postgres" {
		return s
	}
	n := 0
	var b strings.Builder
	for _, c := range s {
		if c == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

func (r *rawTrust) crl() crlRow {
	r.t.Helper()
	rows, err := r.db.Query("SELECT thumbprint, der, issuer_key, number, created_at FROM trust_material WHERE kind = 'leaf_crl'")
	if err != nil {
		r.t.Fatalf("raw read of the leaf CRL: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []crlRow
	for rows.Next() {
		var c crlRow
		if err := rows.Scan(&c.thumbprint, &c.der, &c.issuerKey, &c.number, &c.createdAt); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		r.t.Fatal(err)
	}
	if len(out) != 1 {
		r.t.Fatalf("the database holds %d leaf CRL rows, want 1", len(out))
	}
	return out[0]
}

func (r *rawTrust) number() int64 {
	r.t.Helper()
	var n int64
	if err := r.db.QueryRow("SELECT number FROM trust_material WHERE kind = 'trust_number'").Scan(&n); err != nil {
		r.t.Fatalf("raw read of the trust number: %v", err)
	}
	return n
}

// put writes the leaf CRL row and the trust number back to an older state, as
// a restore from backup does.
func (r *rawTrust) put(c crlRow, number int64) {
	r.t.Helper()
	tx, err := r.db.Begin()
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := tx.Exec(r.q("UPDATE trust_material SET thumbprint = ?, der = ?, number = ?, created_at = ? WHERE kind = 'leaf_crl' AND issuer_key = ?"),
		c.thumbprint, c.der, c.number, c.createdAt, c.issuerKey); err != nil {
		_ = tx.Rollback()
		r.t.Fatalf("raw rollback of the leaf CRL: %v", err)
	}
	if _, err := tx.Exec(r.q("UPDATE trust_material SET number = ? WHERE kind = 'trust_number'"), number); err != nil {
		_ = tx.Rollback()
		r.t.Fatalf("raw rollback of the trust number: %v", err)
	}
	if err := tx.Commit(); err != nil {
		r.t.Fatal(err)
	}
}

// revokedSerials is the serial numbers (hex) a CRL lists.
func revokedSerials(t *testing.T, der []byte) []string {
	t.Helper()
	crl, err := pki.ParseCRL(der)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	var out []string
	for _, e := range crl.RevokedCertificateEntries {
		out = append(out, pki.SerialText(e.SerialNumber))
	}
	return out
}

var trustNumberLineRE = regexp.MustCompile(`(?m)^trust-number (\d+)$`)

// TestRestore is Decision 27 on both engines: a database restored from a
// backup (the leaf CRL and the trust number older than before) must not make
// a client that is already open trust less than it did, and the server must
// not hand out a trust number a client has seen with other contents. One real
// server (cmd.Run on an address the test reserves, so that it can be stopped
// and started again on it) and one client (client.Open over a profile in a
// temporary configuration directory, opened once and kept) serve the whole
// test.
func TestRestore(t *testing.T) {
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rst, _, dsn := openStoreDSN(t, e)
		fix := serverTrust(t, rst)
		sets := fix.Sets()
		raw := openRawTrust(t, e, dsn)

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		issuer := "http://" + addr

		var (
			srv     *replica
			srvStop context.CancelFunc
		)
		start := func() {
			t.Helper()
			sctx, c := context.WithCancel(ctx)
			srv, srvStop = nil, c
			srv = startReplica(t, sctx, "S", e, dsn, append([]string{"-listen", addr, "-set", "issuer=" + issuer}, sets...)...)
		}
		stopServer := func() {
			t.Helper()
			if srv == nil {
				return
			}
			srvStop()
			select {
			case code := <-srv.done:
				if code != 0 {
					t.Errorf("server: Run returned %d after cancel, want 0; stderr %q", code, srv.stderr.String())
				}
			case <-time.After(10 * time.Second):
				t.Errorf("server: Run did not return within 10 s of cancel")
			}
			srv = nil
		}
		start()
		defer stopServer()

		storeFlag := "-sqlite"
		if e.Name == "postgres" {
			storeFlag = "-postgres"
		}
		admin := func(args ...string) (int, string, string) {
			var so, se bytes.Buffer
			code := cmd.RunAdmin(ctx, append([]string{storeFlag, dsn}, append(sets, args...)...), nil, &so, &se)
			return code, so.String(), se.String()
		}
		// hostRevoke lists one serial number no leaf row has, so that no later
		// forced renewal lists it again; it returns the trust number.
		hostRevoke := func(serial string) int64 {
			t.Helper()
			code, out, se := admin("signing-key", "revoke", "-serial", serial)
			if code != 0 {
				t.Fatalf("signing-key revoke -serial %s: %d %s", serial, code, se)
			}
			m := trustNumberLineRE.FindStringSubmatch(out)
			if m == nil {
				t.Fatalf("signing-key revoke printed no trust number: %q", out)
			}
			n, _ := strconv.ParseInt(m[1], 10, 64)
			return n
		}

		// The client: an administrator (so that it can force the renewals) with a
		// credential in a profile of its own.
		pat := newReplicaWho(t, "pat")
		srv.register(t, ctx, pat)
		if code, so, se := admin("admins", "add", "-identity", "pat"); code != 0 {
			t.Fatalf("admins add: %d %s%s", code, so, se)
		}
		env := testkit.NewProfileEnv(t)
		env.Save(t, profile.Profile{Name: "default", Mode: profile.ModeLocal},
			profile.Profile{Name: "lab", Mode: profile.ModeServer, Server: issuer})
		if err := (credential.Store{Dir: profile.CredentialDir(env.Config, "lab")}).Save("pat", pat.key); err != nil {
			t.Fatal(err)
		}
		conn, err := client.Open(ctx, client.Options{Environ: env.Environ, Cwd: env.Home, Profile: "lab", Identity: "pat"})
		if err != nil {
			t.Fatalf("client.Open: %v", err)
		}
		defer func() { _ = conn.Close() }()
		b := conn.Bus
		ts := trust.Store{Dir: trust.Dir(env.Config, "lab")}

		// What the client holds, read from its trust directory.
		heldNumber := func() int64 {
			t.Helper()
			n, ok, err := ts.TrustNumber()
			if err != nil || !ok {
				t.Fatalf("the client's trust number: %d %v %v", n, ok, err)
			}
			return n
		}
		heldCRLNumber := func() int64 {
			t.Helper()
			files, err := filepath.Glob(filepath.Join(ts.Dir, "leaf-*.crl"))
			if err != nil || len(files) != 1 {
				t.Fatalf("the client holds %d leaf CRL files (%v), want 1", len(files), err)
			}
			pem, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			crl, err := pki.ParseCRLPEM(pem)
			if err != nil {
				t.Fatal(err)
			}
			return pki.CRLNumber(crl)
		}
		keptRevoked := func(serial string) bool {
			t.Helper()
			revs, err := ts.Revocations()
			if err != nil {
				t.Fatal(err)
			}
			for _, list := range revs.Leaves {
				if slices.Contains(list, serial) {
					return true
				}
			}
			return false
		}
		refusedLines := func() []string {
			t.Helper()
			raw, err := os.ReadFile(filepath.Join(env.Data, "logs", "trust.log"))
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, l := range strings.Split(string(raw), "\n") {
				if strings.Contains(l, "was refused") {
					out = append(out, l)
				}
			}
			return out
		}
		sess, err := b.Open(ctx, ab2bus.OpenSessionInput{})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		receive := func() ab2bus.ReceiveResult {
			t.Helper()
			res, err := b.Receive(ctx, ab2bus.ReceiveInput{Session: sess.ID})
			if err != nil {
				t.Fatalf("Receive: %v", err)
			}
			return res
		}
		rotate := func() ab2bus.SigningKeyRotation {
			t.Helper()
			rot, err := b.RotateSigningKey(ctx, ab2bus.RotateSigningKeyInput{})
			if err != nil {
				t.Fatalf("RotateSigningKey: %v", err)
			}
			return rot
		}

		// Before the rollback: a first renewal (c1 lists the leaf the server
		// started with); the state it left is what the rollback restores. Then a
		// serial number no leaf row has (X), and a second renewal; c2 lists X and
		// the leaf the first renewal made. The client reads both.
		const serialX = "abcdef01"
		var issued []int64
		rot1 := rotate()
		issued = append(issued, rot1.TrustNumber)
		receive()
		c1, t1 := raw.crl(), raw.number()
		if t1 != rot1.TrustNumber {
			t.Fatalf("the stored trust number %d, want the first renewal's %d", t1, rot1.TrustNumber)
		}
		xNumber := hostRevoke(serialX)
		issued = append(issued, xNumber)
		rot2 := rotate()
		issued = append(issued, rot2.TrustNumber)
		if got := receive(); got.Trust == nil || got.TrustNumber == nil || *got.TrustNumber != rot2.TrustNumber {
			t.Fatalf("Receive after the second renewal = trust %v number %v, want the bundle at %d", got.Trust, got.TrustNumber, rot2.TrustNumber)
		}
		c2 := raw.crl()
		if c2.number <= c1.number || rot2.TrustNumber <= t1 {
			t.Fatalf("numbers did not rise: CRL %d -> %d, trust %d -> %d", c1.number, c2.number, t1, rot2.TrustNumber)
		}
		if heldNumber() != rot2.TrustNumber || heldCRLNumber() != c2.number {
			t.Fatalf("the client holds trust %d and CRL %d, want %d and %d", heldNumber(), heldCRLNumber(), rot2.TrustNumber, c2.number)
		}
		for _, s := range []string{serialX, rot1.Current.Serial} {
			if !slices.Contains(revokedSerials(t, c2.der), s) || !keptRevoked(s) {
				t.Fatalf("serial %s is not in c2 and in the client's kept revocations", s)
			}
		}
		if slices.Contains(revokedSerials(t, c1.der), serialX) {
			t.Fatalf("c1 lists %s already", serialX)
		}
		before := slices.Clone(issued)

		// The restore: the server is stopped, the stored leaf CRL and the trust
		// number are put back, and the server starts again on the same address, so
		// that its memory knows nothing newer than the rolled-back rows.
		stopServer()
		raw.put(c1, t1)
		start()

		// (1) The client's Bus, open since before the restart, gets the bundle
		// on its next receive because the numbers differ, although the server's
		// number is the lower one (Decision 27). A client that sent a bundle
		// only for a higher server number (a "less than" test) fails here.
		t.Run("bundle-after-restore", func(t *testing.T) {
			if got := raw.number(); got != t1 {
				t.Fatalf("the restarted server's stored number %d, want the rolled-back %d", got, t1)
			}
			got := receive()
			if got.Trust == nil || got.TrustNumber == nil {
				t.Fatalf("Receive after the restore carried no bundle (trust %v) while the client holds %d and the server %d", got.Trust, rot2.TrustNumber, t1)
			}
			if *got.TrustNumber != t1 || *got.TrustNumber >= rot2.TrustNumber {
				t.Fatalf("the restarted server's number is %d, want the rolled-back %d, below the client's %d", *got.TrustNumber, t1, rot2.TrustNumber)
			}
		})

		// (2) The older CRL is refused, once, in trust.log; the kept revocations
		// still hold what c2 listed and the recorded number is the server's.
		t.Run("older-crl-refused-once", func(t *testing.T) {
			if lines := refusedLines(); len(lines) != 1 ||
				!strings.Contains(lines[0], fmt.Sprintf("CRL number %d is below the held number %d", c1.number, c2.number)) {
				t.Fatalf("trust.log refusal lines = %q, want one naming %d below %d", lines, c1.number, c2.number)
			}
			if got := receive(); got.Trust != nil {
				t.Fatalf("a second Receive carried a bundle again: %+v", got.Trust)
			}
			if lines := refusedLines(); len(lines) != 1 {
				t.Fatalf("after another Receive trust.log has %d refusal lines, want 1: %q", len(lines), lines)
			}
			if !keptRevoked(serialX) || !keptRevoked(rot1.Current.Serial) {
				t.Fatalf("the client's kept revocations lost a serial number c2 listed")
			}
			if heldNumber() != t1 || heldCRLNumber() != c2.number {
				t.Fatalf("the client holds trust %d and CRL %d, want the server's %d and the kept %d", heldNumber(), heldCRLNumber(), t1, c2.number)
			}
		})

		// (3) The next renewal's CRL has a higher number than the client holds
		// and is accepted: the client's kept CRL moves on and nothing more is
		// refused.
		var afterFirst int64
		t.Run("next-renewal-accepted", func(t *testing.T) {
			rot3 := rotate()
			afterFirst = rot3.TrustNumber
			c3 := raw.crl()
			if c3.number <= c2.number {
				t.Fatalf("the next CRL's number %d is not above the held %d", c3.number, c2.number)
			}
			if got := receive(); got.Trust == nil || got.TrustNumber == nil || *got.TrustNumber != rot3.TrustNumber {
				t.Fatalf("Receive after the next renewal = trust %v number %v, want the bundle at %d", got.Trust, got.TrustNumber, rot3.TrustNumber)
			}
			if heldCRLNumber() != c3.number || heldNumber() != rot3.TrustNumber {
				t.Fatalf("the client holds CRL %d and trust %d, want %d and %d", heldCRLNumber(), heldNumber(), c3.number, rot3.TrustNumber)
			}
			if !keptRevoked(rot2.Current.Serial) {
				t.Fatalf("the client does not list %s, which the accepted CRL revoked", rot2.Current.Serial)
			}
			if lines := refusedLines(); len(lines) != 1 {
				t.Fatalf("trust.log has %d refusal lines, want still 1: %q", len(lines), lines)
			}
		})

		// (4) A serial number the restored server's CRLs never listed (X was only
		// in c2) is still in the client's kept revocations: the client's set is a
		// union, never replaced.
		t.Run("union-on-the-client", func(t *testing.T) {
			if slices.Contains(revokedSerials(t, raw.crl().der), serialX) {
				t.Fatalf("the server's new CRL lists %s; the scenario needs it missing", serialX)
			}
			if !keptRevoked(serialX) {
				t.Fatalf("the client's kept revocations lost %s", serialX)
			}
		})

		// (5) The same on the server with the process kept running across a
		// rollback: it remembers the CRL it verified (and writes it back on its
		// next reload), so the next CRL it builds lists the serial number the
		// rolled-back row lost (Y). Which of the two the running server reaches
		// first (the reload its own doorbell causes, or the renewal's) is not
		// observable here; both end with Y listed.
		var afterSecond int64
		var beforeSecond []int64
		t.Run("union-on-the-server", func(t *testing.T) {
			c3, t3 := raw.crl(), raw.number()
			const serialY = "feedbeef"
			yNumber := hostRevoke(serialY)
			// The admin list reloads, so the running server's memory holds the CRL
			// that lists Y before the rows go back.
			if _, err := b.ListSigningKeys(ctx); err != nil {
				t.Fatalf("ListSigningKeys: %v", err)
			}
			if !slices.Contains(revokedSerials(t, raw.crl().der), serialY) {
				t.Fatalf("the CRL after the host revocation does not list %s", serialY)
			}
			beforeSecond = append(slices.Clone(issued), afterFirst, yNumber)
			raw.put(c3, t3)
			if slices.Contains(revokedSerials(t, raw.crl().der), serialY) {
				t.Fatalf("the rolled-back CRL still lists %s", serialY)
			}
			rot4 := rotate()
			afterSecond = rot4.TrustNumber
			if !slices.Contains(revokedSerials(t, raw.crl().der), serialY) {
				t.Fatalf("the CRL the running server built after the rollback lacks %s", serialY)
			}
		})

		// (6) The trust number of the first change after a rollback is above
		// every value issued before it, so no number a client has seen comes back
		// with other contents.
		t.Run("trust-number-above-all", func(t *testing.T) {
			if afterFirst == 0 || afterSecond == 0 {
				t.Fatal("the earlier subtests did not run to their changes")
			}
			for _, n := range before {
				if afterFirst <= n {
					t.Errorf("the first change after the restart has number %d, not above %d issued before it", afterFirst, n)
				}
			}
			for _, n := range beforeSecond {
				if afterSecond <= n {
					t.Errorf("the first change after the second rollback has number %d, not above %d issued before it", afterSecond, n)
				}
			}
		})
	})
}

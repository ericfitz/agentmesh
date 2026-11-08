package sqlstore

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"testing"
)

// fakeNetErr is a net.Error, the shape pgx's connect error unwraps to when
// the Postgres server cannot be reached.
type fakeNetErr struct{}

func (fakeNetErr) Error() string   { return "dial tcp 10.0.0.1:5432: connect: connection refused" }
func (fakeNetErr) Timeout() bool   { return false }
func (fakeNetErr) Temporary() bool { return false }

// TestIsOutage pins what counts as a store outage (503 unavailable) and what
// stays an unclassified error: a net.Error reached through wrapping (the
// Postgres path), a closed or dead handle, and nothing else.
func TestIsOutage(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"net error":         {fakeNetErr{}, true},
		"wrapped net error": {fmt.Errorf("failed to connect to `user=app database=agentmesh`: %w", fakeNetErr{}), true},
		"conn done":         {sql.ErrConnDone, true},
		"bad conn":          {fmt.Errorf("begin: %w", driver.ErrBadConn), true},
		"closed database":   {errors.New("sql: database is closed"), true},
		"statement error":   {errors.New("no such table: nope"), false},
		"no rows":           {sql.ErrNoRows, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := isOutage(tc.err); got != tc.want {
				t.Errorf("isOutage(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

package server

import (
	"fmt"
	"os"
	"testing"

	"github.com/ericfitz/agentmesh/internal/respcheck"
)

// TestMain fails the run when a response violation arrived after its test had
// finished (a goroutine outliving it): respcheck.Report sends those to Late.
func TestMain(m *testing.M) {
	code := m.Run()
	if late := respcheck.Late(); code == 0 && len(late) != 0 {
		fmt.Fprintf(os.Stderr, "response validation: %d violations after their test finished, first: %v\n", len(late), late[0])
		code = 1
	}
	os.Exit(code)
}

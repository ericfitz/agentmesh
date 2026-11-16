package core_test

import (
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
)

type fixedTrust struct{ b bus.TrustBundle }

func (f fixedTrust) Bundle() bus.TrustBundle { return f.b }

func (f fixedTrust) Signing() bus.HealthSigning { return bus.HealthSigning{} }

func TestInBand(t *testing.T) {
	src := fixedTrust{bus.TrustBundle{TrustNumber: 7, Intermediates: [][]byte{{1}}, Root: []byte{9}, Installation: "inst"}}
	num := func(n int64) *int64 { return &n }
	for _, c := range []struct {
		name   string
		client *int64
		attach bool
	}{{"lower", num(6), true}, {"equal", num(7), false}, {"higher", num(8), true}, {"absent", nil, true}} {
		t.Run(c.name, func(t *testing.T) {
			n, b := core.InBand(src, c.client)
			if n == nil || *n != 7 {
				t.Fatalf("number = %v", n)
			}
			if (b != nil) != c.attach {
				t.Fatalf("bundle = %v, want present %v", b, c.attach)
			}
			if b != nil && (b.Root != nil || b.Installation != "" || len(b.Intermediates) != 1) {
				t.Fatalf("bundle = %+v: no root, no installation, the intermediates kept", b)
			}
		})
	}
	if n, b := core.InBand(nil, nil); n != nil || b != nil {
		t.Fatal("a nil source attached something")
	}
}

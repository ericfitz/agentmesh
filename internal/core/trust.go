package core

import "github.com/ericfitz/agentmesh/internal/bus"

// TrustSource is the process's verified, in-memory copy of the trust material (the leaf manager in
// server mode; nil in local mode). Nothing behind it touches the Store.
type TrustSource interface {
	Bundle() bus.TrustBundle // with Root and Installation
	// Signing is the health document's signing section at the source's clock; like
	// Bundle it never waits for a load.
	Signing() bus.HealthSigning
}

// Trust is the process's trust source, nil in local mode.
func (c *Core) Trust() TrustSource { return c.trust }

// InBand is what session open and receive attach (section 4.9): always the number; the bundle,
// without Root and Installation, when the client's number is absent or differs (Decision 27).
// A nil source (local mode) attaches nothing.
func InBand(ts TrustSource, client *int64) (number *int64, bundle *bus.TrustBundle) {
	if ts == nil {
		return nil, nil
	}
	b := ts.Bundle()
	n := b.TrustNumber
	if client == nil || *client != b.TrustNumber {
		b.Root, b.Installation = nil, ""
		return &n, &b
	}
	return &n, nil
}

package signingkeys

import "context"

// SetChainCheckHook sets the function Load calls before each pki.CheckChain
// (nil clears it): the tests count chain verifications through it.
func SetChainCheckHook(f func()) { chainCheckHook = f }

// Issue issues one leaf the way a renewal does (tests only; Step is the production path).
func (m *Manager) Issue(ctx context.Context) error { return m.issue(ctx) }

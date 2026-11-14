package signingkeys

import "context"

// SetChainCheckHook sets the function Load calls before each pki.CheckChain
// (nil clears it): the tests count chain verifications through it.
func SetChainCheckHook(f func()) { chainCheckHook = f }

// Issue issues one leaf the way a renewal does (tests only; Step is the production path).
func (m *Manager) Issue(ctx context.Context) error { return m.issue(ctx) }

// Wake is the channel Reload fills when it makes an issue due and Run waits on.
func (m *Manager) Wake() <-chan struct{} { return m.wake }

// SetRunParkedHook sets the function Run calls just before it waits for its
// timer, the wake channel or its context (nil clears it).
func SetRunParkedHook(f func()) { runParkedHook = f }

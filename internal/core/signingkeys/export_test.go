package signingkeys

// SetChainCheckHook sets the function Load calls before each pki.CheckChain
// (nil clears it): the tests count chain verifications through it.
func SetChainCheckHook(f func()) { chainCheckHook = f }

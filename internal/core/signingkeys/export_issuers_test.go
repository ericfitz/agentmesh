package signingkeys

// IssuerCount is the number of leaves whose verifying keys the Memory holds.
func (m *Memory) IssuerCount() int { return len(m.issuers) }

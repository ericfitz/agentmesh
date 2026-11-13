// Package pki holds the certificate profiles of the agentmesh certificate
// hierarchy (ADR 0019, spec section 4.2): a root, one intermediate per
// installation and a short-lived Ed25519 leaf, plus the identifier of the
// agentmesh extended key usage, installation names, thumbprints and PEM
// parsing. It imports the standard library only.
package pki

// Package respcheck validates HTTP responses against an OpenAPI document at
// run time. It is test support (issue #33): the e2e and conformance paths wrap
// their client or server in a Transport or Proxy and fail on any response the
// document does not declare. Production code never imports it; the m4 import
// rule (scripts/m4-exit-checks.sh) proves neither binary links it. It imports
// the standard library and kin-openapi only, nothing of this module: the
// document is a parameter.
package respcheck

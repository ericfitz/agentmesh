// Package arazzotest is a small test-only runner for Arazzo 1.0 workflows
// (issue #32, Eric's decision 3). It loads an Arazzo document and the one
// OpenAPI document it names, binds every step's operationId to a method and
// path, and runs a workflow's steps against a base URL (the e2e validating
// proxy). Test code only: the m4 import rule (scripts/m4-exit-checks.sh)
// proves neither binary links it. It imports the standard library,
// kin-openapi's openapi3 and gopkg.in/yaml.v3, nothing of this module.
//
// Supported: one openapi source description (a relative file path); workflows
// with inputs (required names and declared properties), dependsOn (checked,
// never run), steps by operationId with path, query and header parameters, a
// JSON or form-urlencoded request body, success criteria of the form
// "<lhs> == <literal>" or "<lhs> != <literal>" (lhs is $statusCode or
// $response.body#/<pointer>) and step and workflow outputs; the expressions
// $inputs.x, $steps.s.outputs.x, $statusCode, $response.body and
// $response.body#/pointer, bare or embedded in a string as {expr}.
//
// Everything else is refused by name with an *UnsupportedError, never
// ignored: Unsupported lists every refusal, and each has a fixture.
package arazzotest

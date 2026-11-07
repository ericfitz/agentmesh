package arazzotest

import (
	"fmt"
	"sort"
)

// The features the runner refuses. Every *UnsupportedError carries one of
// these as Feature (an unknown key appends the key to featUnknownKey's
// prefix).
const (
	featVersion       = "arazzo version"
	featUnknownKey    = "unknown key <k>"
	featSecondSource  = "second sourceDescription"
	featSourceType    = "sourceDescription type"
	featSourceURL     = "sourceDescription url"
	featComponents    = "components"
	featWFParameters  = "workflow parameters"
	featSuccessActs   = "successActions"
	featFailureActs   = "failureActions"
	featOperationPath = "operationPath"
	featStepWorkflow  = "step workflowId"
	featOnSuccess     = "onSuccess"
	featOnFailure     = "onFailure"
	featReferenceParm = "reference parameter"
	featReplacements  = "requestBody replacements"
	featCookie        = "parameter in cookie"
	featParamLocation = "parameter location"
	featCritType      = "criterion type"
	featCritContext   = "criterion context"
	featContentType   = "contentType"
	featCondition     = "condition syntax"
	featExprURL       = "expression $url"
	featExprMethod    = "expression $method"
	featExprRequest   = "expression $request"
	featExprHeader    = "expression $response.header"
	featExprSources   = "expression $sourceDescriptions"
	featExprWorkflows = "expression $workflows"
	featExprComps     = "expression $components"
	featExprOther     = "unrecognized expression"
)

var unsupportedFeatures = []string{
	featVersion, featUnknownKey, featSecondSource, featSourceType, featSourceURL,
	featComponents, featWFParameters, featSuccessActs, featFailureActs,
	featOperationPath, featStepWorkflow, featOnSuccess, featOnFailure,
	featReferenceParm, featReplacements, featCookie, featParamLocation,
	featCritType, featCritContext, featContentType, featCondition,
	featExprURL, featExprMethod, featExprRequest, featExprHeader,
	featExprSources, featExprWorkflows, featExprComps, featExprOther,
}

// Unsupported lists every Feature an *UnsupportedError can carry, sorted. An
// unknown key is listed as "unknown key <k>" and reported as "unknown key
// <the key>".
func Unsupported() []string {
	out := append([]string(nil), unsupportedFeatures...)
	sort.Strings(out)
	return out
}

// UnsupportedError is a refusal: the document uses an Arazzo feature this
// runner does not implement. Where is a path such as
// "workflows[0].steps[2].operationPath" (an unknown key: "line N").
type UnsupportedError struct{ Where, Feature string }

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("arazzotest: %s: unsupported Arazzo feature: %s", e.Where, e.Feature)
}

func unsupported(where, feature string) error {
	return &UnsupportedError{Where: where, Feature: feature}
}

// OrderError reports a dependsOn prerequisite that has not completed in this
// Runner. The runner never runs a prerequisite for the caller.
type OrderError struct{ Workflow, Needs string }

func (e *OrderError) Error() string {
	return fmt.Sprintf("arazzotest: workflow %q depends on %q, which has not completed in this runner", e.Workflow, e.Needs)
}

// CriteriaError reports a step whose success criterion did not hold.
type CriteriaError struct {
	Workflow, Step, Condition string
	Status                    int
	Body                      []byte
}

func (e *CriteriaError) Error() string {
	return fmt.Sprintf("arazzotest: workflow %q step %q: criterion %q failed (status %d, body %s)",
		e.Workflow, e.Step, e.Condition, e.Status, e.Body)
}

// ResolveError reports a name or expression that cannot be resolved: an
// unknown operationId or workflow, an undefined input or step output, a
// pointer that does not resolve, a missing path parameter.
type ResolveError struct {
	Where, Expr string
	Cause       error
}

func (e *ResolveError) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("arazzotest: %s: cannot resolve %s", e.Where, e.Expr)
	}
	return fmt.Sprintf("arazzotest: %s: cannot resolve %s: %v", e.Where, e.Expr, e.Cause)
}

func (e *ResolveError) Unwrap() error { return e.Cause }

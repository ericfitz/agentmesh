package server

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/ericfitz/agentmesh/internal/bus"
)

// statusTable is the one status per code: StatusFor and the shared responses
// agree with it. It is statusByCode (problem_test.go), not a second copy.
var statusTable = statusByCode

// responseFor names the shared response a status is declared through.
var responseFor = map[int]string{
	400: "BadRequest", 401: "Unauthorized", 403: "Forbidden", 404: "NotFound",
	409: "Conflict", 410: "Gone", 413: "PayloadTooLarge", 422: "UnprocessableEntity",
	429: "TooManyRequests", 500: "InternalServerError", 503: "ServiceUnavailable",
}

// tokenStatuses are the statuses of the token endpoint, each an OAuthError
// (oauth.go:52-66, auth_handlers.go, server.go limitBody).
var tokenStatuses = []int{400, 401, 413, 500, 503}

// The three tiers every operation's error set is composed from; an operation
// adds its extras (operationExtras) beyond them.
var (
	tierAll    = []bus.Code{bus.CodeValidation, bus.CodeInternal}                                // T0: every operation
	tierBody   = []bus.Code{bus.CodePayloadTooLarge}                                             // T1: requestBody set
	tierGlobal = []bus.Code{bus.CodeUnauthenticated, bus.CodeNotRegistered, bus.CodeUnavailable} // T2: the global bearerAuth requirement
)

// Short names for the extras table.
const (
	nf  = bus.CodeNotFound
	fb  = bus.CodeForbidden
	cf  = bus.CodeConflict
	sc  = bus.CodeSessionClosed
	sl  = bus.CodeSessionLapsed
	rl  = bus.CodeRateLimited
	ir  = bus.CodeInspectionRejected
	rp  = bus.CodeReplaced
	una = bus.CodeUnavailable
)

// operationExtras are the codes beyond the tiers; every operation has an
// entry, possibly empty. The producing site of each code is listed in the plan's
// "per-operation table" (docs/superpowers/plans/2026-11-07-issue-33-error-responses.md).
var operationExtras = map[string][]bus.Code{
	"wellKnown": {}, "authorizationServerMetadata": {}, "openidConfiguration": {}, "discover": {},
	// open operation: no global requirement, so its 401, 403 and 503 are extras.
	"health":         {bus.CodeUnauthenticated, bus.CodeNotRegistered, una},
	"openSession":    {nf, sc},
	"closeSession":   {nf, cf},
	"receive":        {nf, sc, sl},
	"watch":          {nf, sc, sl, rp},
	"peek":           {nf, sc, sl},
	"listIdentities": {}, "listAgentStatuses": {}, "listChannels": {}, "listTagSubscriptions": {},
	"setAgentStatus":      {fb, nf, sc, sl, rl, cf},
	"agentStatusHistory":  {nf},
	"createChannel":       {fb, nf, cf},
	"deleteChannel":       {fb, nf, cf},
	"renameChannel":       {fb, nf, cf},
	"getACL":              {fb, nf},
	"setACL":              {fb, nf, cf},
	"subscribe":           {fb, nf, cf},
	"unsubscribe":         {fb, nf, cf},
	"subscribeTags":       {cf},
	"unsubscribeTags":     {cf},
	"sendMessage":         {fb, nf, sc, sl, cf, ir, rl},
	"history":             {fb, nf},
	"search":              {fb, nf},
	"getMemory":           {fb, nf},
	"listMemoryRevisions": {fb, nf},
	"deleteMemory":        {fb, nf, rl, cf},
	"editMemory":          {fb, nf, cf, ir, rl},
	"createTask":          {fb, nf, cf, ir, rl},
	"listTasks":           {fb, nf},
	"getTask":             {fb, nf},
	"updateTask":          {fb, nf, cf, ir, rl},
	"claimTask":           {fb, nf, cf, ir, rl},
	"releaseTask":         {fb, nf, cf, ir, rl},
	"adminStatus":         {fb},
	"adminUsage":          {fb},
	"listScopes":          {fb},
	"token":               {}, // compared with tokenStatuses
	// open operation: unavailable only (no store row is read).
	"jwks":                  {una},
	"register":              {fb, cf, una},
	"adminReset":            {fb, cf},
	"resetCredential":       {fb, nf, cf},
	"listSigningKeys":       {fb},
	"rotateSigningKey":      {fb, cf},
	"createIdentityByEmail": {fb, cf},
	"createAgentIdentity":   {fb, nf, cf},
	"createScope":           {fb, cf},
	"getScope":              {fb, nf},
	"doneScope":             {fb, nf, cf},
	"createBridge":          {fb, nf, cf, rl},
	"listBridges":           {fb},
	"getBridge":             {fb, nf},
	// the Slack archive call of a remove answers rate_limited (slackbridge/archive.go:61,67).
	"removeBridge": {fb, nf, rl},
}

const problemJSON = "application/problem+json"

func sortedStatuses(set map[int][]bus.Code) []int {
	out := make([]int, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Ints(out)
	return out
}

func codeNames(codes []bus.Code) string {
	names := make([]string, len(codes))
	for i, c := range codes {
		names[i] = string(c)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// operationsOf returns every operation of the document by operationId as
// api/openapi.yaml spells it: the embedded document carries the generator's
// capitalized ids ("SendMessage"), so the first letter is lowered.
func operationsOf(doc *openapi3.T) map[string]*openapi3.Operation {
	out := map[string]*openapi3.Operation{}
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			out[strings.ToLower(op.OperationID[:1])+op.OperationID[1:]] = op
		}
	}
	return out
}

// declaredErrors maps each non-2xx status an operation declares to its
// $ref target (a name under components/responses), "" for an inline one.
func declaredErrors(t *testing.T, id string, op *openapi3.Operation) map[int]string {
	t.Helper()
	out := map[int]string{}
	for key, ref := range op.Responses.Map() {
		if strings.HasPrefix(key, "2") {
			continue
		}
		s, err := strconv.Atoi(key)
		if err != nil {
			continue // "default" and ranges: TestStatusTable/references reports them
		}
		out[s] = strings.TrimPrefix(ref.Ref, "#/components/responses/")
	}
	return out
}

func TestStatusTable(t *testing.T) {
	doc := Spec()

	t.Run("status_for", func(t *testing.T) {
		all := map[bus.Code]bool{}
		for _, c := range bus.Codes() {
			all[c] = true
			if _, ok := statusTable[c]; !ok {
				t.Errorf("bus code %q has no status in statusTable", c)
			}
		}
		if len(statusTable) != 14 || len(all) != 14 {
			t.Fatalf("statusTable has %d codes, bus.Codes() %d, want 14", len(statusTable), len(all))
		}
		for code, status := range statusTable {
			if got := StatusFor(code); got != status {
				t.Errorf("StatusFor(%s) = %d, want %d", code, got, status)
			}
			if !all[code] {
				t.Errorf("%s is in statusTable but not in bus.Codes()", code)
			}
		}
		problem := doc.Components.Schemas["Problem"]
		if problem == nil {
			t.Fatal("no Problem schema")
		}
		enum := map[bus.Code]bool{}
		for _, v := range problem.Value.Properties["code"].Value.Enum {
			c := bus.Code(fmt.Sprint(v))
			enum[c] = true
			if _, ok := statusTable[c]; !ok {
				t.Errorf("spec code %q has no status in statusTable", c)
			}
			if !all[c] {
				t.Errorf("spec code %q is not in bus.Codes()", c)
			}
		}
		for code := range statusTable {
			if !enum[code] {
				t.Errorf("code %q is in statusTable but not in the spec's Problem.code enum", code)
			}
		}
		for c := range all {
			if !enum[c] {
				t.Errorf("bus code %q is not in the spec's Problem.code enum", c)
			}
		}
	})

	t.Run("shared_responses", func(t *testing.T) {
		names := map[string]bool{}
		for status, name := range responseFor {
			names[name] = true
			ref := doc.Components.Responses[name]
			if ref == nil || ref.Value == nil {
				t.Errorf("%d: components/responses/%s does not exist", status, name)
				continue
			}
			mt := ref.Value.Content[problemJSON]
			if mt == nil || mt.Schema == nil || mt.Schema.Value == nil {
				t.Errorf("%s: no %s schema", name, problemJSON)
				continue
			}
			all := mt.Schema.Value.AllOf
			if len(all) != 2 || all[0].Ref != "#/components/schemas/Problem" || all[1].Value == nil {
				t.Errorf("%s: schema is not an allOf of $ref Problem and an object", name)
				continue
			}
			codeProp := all[1].Value.Properties["code"]
			if codeProp == nil || codeProp.Value == nil {
				t.Errorf("%s: the narrowing object has no code property", name)
				continue
			}
			var got, want []string
			for _, v := range codeProp.Value.Enum {
				got = append(got, fmt.Sprint(v))
			}
			for code, s := range statusTable {
				if s == status {
					want = append(want, string(code))
				}
			}
			sort.Strings(got)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Errorf("%s (%d): code enum %v, statusTable says %v", name, status, got, want)
			}
		}
		for status := range func() map[int]bool {
			m := map[int]bool{}
			for _, s := range statusTable {
				m[s] = true
			}
			return m
		}() {
			if _, ok := responseFor[status]; !ok {
				t.Errorf("status %d has no shared response in responseFor", status)
			}
		}
		for name, ref := range doc.Components.Responses {
			if ref.Value.Content[problemJSON] != nil && !names[name] {
				t.Errorf("components/responses/%s carries %s but is not a responseFor entry", name, problemJSON)
			}
		}
		tm := doc.Components.Responses["TooManyRequests"].Value
		h := tm.Headers["Retry-After"]
		switch {
		case h == nil || h.Value == nil:
			t.Error("TooManyRequests declares no Retry-After header")
		case !h.Value.Required:
			t.Error("TooManyRequests: Retry-After is not required")
		case h.Value.Schema == nil || h.Value.Schema.Value == nil || !h.Value.Schema.Value.Type.Is("integer"):
			t.Error("TooManyRequests: Retry-After is not an integer")
		}
	})

	t.Run("references", func(t *testing.T) {
		ops := operationsOf(doc)
		for id, op := range ops {
			if op.Responses.Default() != nil {
				t.Errorf("%s declares a default response", id)
			}
			for key := range op.Responses.Map() {
				if _, err := strconv.Atoi(key); err != nil && key != "default" {
					t.Errorf("%s: response key %q is not a status", id, key)
				}
			}
			for status, name := range declaredErrors(t, id, op) {
				want := responseFor[status]
				if id == "token" {
					want = "OAuthError"
				}
				if name != want {
					t.Errorf("%s: %d is declared through %q, want the shared response %q", id, status, name, want)
				}
			}
		}
	})
}

func TestOperationErrorTable(t *testing.T) {
	doc := Spec()
	ops := operationsOf(doc)

	for id, op := range ops {
		t.Run(id, func(t *testing.T) {
			declared := declaredErrors(t, id, op)
			if id == "token" {
				var got []int
				for s := range declared {
					got = append(got, s)
				}
				sort.Ints(got)
				if !slices.Equal(got, tokenStatuses) {
					t.Errorf("token declares %v, want %v", got, tokenStatuses)
				}
				return
			}
			codes := append([]bus.Code{}, tierAll...)
			if op.RequestBody != nil {
				codes = append(codes, tierBody...)
			}
			if op.Security == nil {
				codes = append(codes, tierGlobal...)
			}
			extras, ok := operationExtras[id]
			if !ok {
				t.Fatalf("operationExtras has no entry for %s", id)
			}
			codes = append(codes, extras...)
			want := map[int][]bus.Code{}
			for _, c := range codes {
				s := StatusFor(c)
				if !slices.Contains(want[s], c) {
					want[s] = append(want[s], c)
				}
			}
			for _, s := range sortedStatuses(want) {
				if _, ok := declared[s]; !ok {
					t.Errorf("%d is produced (%s) but not declared", s, codeNames(want[s]))
				}
			}
			for s := range declared {
				if _, ok := want[s]; !ok {
					t.Errorf("%d is declared but no code produces it (the table lists none)", s)
				}
			}
		})
	}

	t.Run("staleness", func(t *testing.T) {
		for id := range operationExtras {
			if _, ok := ops[id]; !ok {
				t.Errorf("operationExtras names %s, which the document lacks", id)
			}
		}
		for id := range ops {
			if _, ok := operationExtras[id]; !ok {
				t.Errorf("operationExtras lacks %s, which the document has", id)
			}
		}
		if !sort.IntsAreSorted(tokenStatuses) {
			t.Error("tokenStatuses is not sorted")
		}
		for i := 1; i < len(tokenStatuses); i++ {
			if tokenStatuses[i] == tokenStatuses[i-1] {
				t.Errorf("tokenStatuses repeats %d", tokenStatuses[i])
			}
		}
	})
}

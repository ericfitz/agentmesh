package server

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/auth/assertion"
	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/rules"
	"github.com/ericfitz/agentmesh/internal/core/sessions"
	"github.com/ericfitz/agentmesh/internal/core/tasks"
	"github.com/ericfitz/agentmesh/internal/slackapi"
	"github.com/ericfitz/agentmesh/internal/store"
)

// unit is the word the description of a bounded field must contain: what the
// server counts (issue #34, plan "Units, per category").
type unit string

const (
	codePoints unit = "code points"
	bytesUnit  unit = "bytes"
	encoded    unit = "percent-encoded"
	itemsUnit  unit = "items"
	keysUnit   unit = "keys"
	secUnit    unit = "seconds"
	noUnit     unit = "" // a number whose unit is itself
)

// bound is one row: every bounding member the spec must state for a field,
// read from the Go constant behind it. A nil or zero member must be absent
// from the spec.
type bound struct {
	MaxLength *int
	MinLength int
	Pattern   string
	Min, Max  *float64
	Format    string
	MaxItems  *int
	MinItems  int
	MaxProps  *int
	Unit      unit   // the description must contain the word
	Setting   string // the setting whose ceiling this is; the description must name it
	Source    string // the Go constant or site, for the reader
}

func n(v int) *int         { return &v }
func f(v float64) *float64 { return &v }
func i64max() *float64     { return f(math.MaxInt64) }
func idBound(src string) bound {
	return bound{Format: "int64", Min: f(0), Max: i64max(), Source: src + "; rules.NonNegative; the type"}
}
func seqBound(src string) bound { return idBound(src) }

func nameBound(src string) bound {
	return bound{MaxLength: n(store.MaxNameBytes), Unit: bytesUnit, Source: "store.NameRule; " + src}
}
func pathNameBound(src string) bound {
	return bound{MaxLength: n(3 * store.MaxNameBytes), Unit: encoded, Source: "store.NameRule; ruling 15; " + src}
}
func lineBound(src string) bound {
	return bound{MaxLength: n(rules.MaxLineRunes), Unit: codePoints, Source: "rules.MaxLineRunes; " + src}
}
func labelBound(src string) bound {
	return bound{MaxLength: n(rules.MaxLabelRunes), Unit: codePoints, Source: "rules.CheckLabel; " + src}
}
func tokenBound(src string) bound {
	return bound{MaxLength: n(rules.MaxTokenBytes), Unit: bytesUnit, Source: "rules.CheckToken; " + src}
}
func contentBound(src string) bound {
	return bound{MaxLength: n(core.MessageKiBCeiling * 1024), Unit: bytesUnit, Setting: "max_message_kib", Source: "core.MessageKiBCeiling; " + src}
}
func tagsBound(src string) bound {
	return bound{MaxItems: n(rules.MaxTags), Unit: itemsUnit, Source: "rules.NormalizeTags; " + src}
}
func tagItemBound(src string) bound {
	return bound{MaxLength: n(rules.MaxTagLen), Pattern: rules.TagSpecPattern, Unit: codePoints, Source: "rules.MaxTagLen, TagSpecPattern; " + src}
}
func patternsBound(src string) bound {
	return bound{MaxItems: n(rules.MaxTags), Unit: itemsUnit, Source: "rules.NormalizeTagPatterns; " + src}
}
func patternItemBound(src string) bound {
	return bound{MaxLength: n(rules.MaxTagPatternLen), Pattern: rules.TagPatternSpecPattern, Unit: codePoints, Source: "rules.MaxTagPatternLen, TagPatternSpecPattern; " + src}
}
func arrayBound(src string) bound {
	return bound{MaxItems: n(rules.MaxArrayItems), Unit: itemsUnit, Source: "rules.CheckItems; " + src}
}
func metadataBound(src string) bound {
	return bound{MaxProps: n(rules.MaxMetadataKeys), Unit: keysUnit, Source: "rules.CheckMetadata; " + src}
}
func metadataValueBound(src string) bound {
	return bound{MaxLength: n(rules.MaxMetadataValueRunes), Unit: codePoints, Source: "rules.CheckMetadata; " + src}
}
func blockersBound(src string) bound {
	return bound{MaxItems: n(tasks.MaxBlockers), Unit: itemsUnit, Source: "tasks.MaxBlockers; " + src}
}
func oauthBound(src string) bound {
	return bound{MaxLength: n(MaxOAuthFieldBytes), Unit: bytesUnit, Source: "server.MaxOAuthFieldBytes; " + src}
}
func jwtBound(src string) bound {
	return bound{MaxLength: n(assertion.MaxTokenBytes), Unit: bytesUnit, Source: "assertion.MaxTokenBytes; " + src}
}
func countBound(max int, setting, src string) bound {
	return bound{Format: "int32", Min: f(0), Max: f(float64(max)), Setting: setting, Source: src}
}

// bounds is the literal table: one row per bounded request field, keyed as
// walkRequests keys it. Every value is a Go constant (or the type), never a
// number typed here.
var bounds = map[string]bound{
	// path and header parameters
	"parameters/SessionParam":                     {MaxLength: n(3 * rules.MaxTokenBytes), Unit: encoded, Source: "rules.MaxTokenBytes; sessions.Require; ruling 15"},
	"parameters/ChannelParam":                     pathNameBound("channel"),
	"parameters/ScopeParam":                       pathNameBound("scope"),
	"operations/agentStatusHistory/path/identity": pathNameBound("identity"),
	"operations/resetCredential/path/identity":    pathNameBound("identity"),
	"parameters/IdParam":                          idBound("id"),
	"parameters/IdempotencyKeyParam":              tokenBound("core.CheckReceipt"),

	// query parameters
	"operations/history/query/after":             idBound("history after"),
	"operations/history/query/before":            idBound("history before"),
	"operations/history/query/count":             countBound(core.ReceiveCountCeiling, "receive_max_count", "core.ReceiveCountCeiling"),
	"operations/history/query/tags":              patternsBound("history tags"),
	"operations/history/query/tags[]":            patternItemBound("history tags"),
	"operations/history/query/thread":            {Format: "int64", Min: f(1), Max: i64max(), Source: "messaging/history.go inline thread < 1 check; the type"},
	"operations/listTasks/query/owner":           nameBound("listTasks owner"),
	"operations/listTasks/query/status":          labelBound("listTasks status"),
	"operations/search/query/channel":            nameBound("search channel"),
	"operations/search/query/count":              countBound(rules.SearchPageMax, "", "rules.SearchPageMax"),
	"operations/search/query/cursor":             {MaxLength: n(rules.MaxSearchCursorLen), Pattern: rules.SearchCursorPattern, Unit: codePoints, Source: "rules.MaxSearchCursorLen; strconv.Atoi"},
	"operations/search/query/q":                  {MaxLength: n(rules.MaxQueryRunes), Unit: codePoints, Source: "rules.MaxQueryRunes; ruling 9"},
	"operations/search/query/sender":             nameBound("search sender"),
	"operations/search/query/since":              idBound("search since"),
	"operations/search/query/tags":               patternsBound("search tags"),
	"operations/search/query/tags[]":             patternItemBound("search tags"),
	"operations/search/query/thread":             {Format: "int64", Min: f(1), Max: i64max(), Source: "rules.AtLeastOne (search/service.go); the type"},
	"operations/search/query/until":              idBound("search until"),
	"operations/unsubscribeTags/query/pattern":   {MaxItems: n(rules.MaxTags), MinItems: 1, Unit: itemsUnit, Source: "rules.NormalizeTagPatterns; unsubscribeTags"},
	"operations/unsubscribeTags/query/pattern[]": patternItemBound("unsubscribeTags"),
	"operations/watch/query/after":               seqBound("watch after"),
	"operations/watch/query/timeout":             {Format: "double", Min: f(0), Max: f(float64(core.WatchSecondsCeiling)), Unit: secUnit, Setting: "watch_max_seconds", Source: "core.WatchSecondsCeiling"},

	// inline request bodies
	"operations/setACL/body": arrayBound("setACL"),

	// request body schemas
	"schemas/ACLEntry.identity":    nameBound("ACL entry identity"),
	"schemas/ACLEntry.permissions": {MaxItems: n(len(store.AllPermissions)), MinItems: 1, Unit: itemsUnit, Source: "store.AllPermissions; core.aclEntries"},

	"schemas/ClaimTaskRequest.leased_until": idBound("claim leased_until"),

	"schemas/CreateAgentIdentityRequest.name":    nameBound("agent identity name"),
	"schemas/CreateAgentIdentityRequest.scope":   nameBound("agent identity scope"),
	"schemas/CreateBridgeRequest.channel":        nameBound("bridge channel"),
	"schemas/CreateBridgeRequest.slack_name":     {MaxLength: n(slackapi.MaxChannelNameLen), Pattern: slackapi.ChannelNamePattern, Unit: codePoints, Source: "slackapi.MaxChannelNameLen, ChannelNamePattern"},
	"schemas/CreateChannelRequest.acl":           arrayBound("createChannel acl"),
	"schemas/CreateChannelRequest.name":          nameBound("channel name"),
	"schemas/CreateChannelRequest.scope":         nameBound("channel scope"),
	"schemas/CreateIdentityByEmailRequest.email": nameBound("human email"),
	"schemas/CreateScopeRequest.name":            nameBound("scope name"),

	"schemas/EditMemoryRequest.content":        contentBound("editMemory content"),
	"schemas/EditMemoryRequest.if_revision":    {Format: "int64", Min: f(1), Max: i64max(), Source: "memories/memories.go inline if_revision < 0 check; the type (the core also accepts 0 as no check)"},
	"schemas/EditMemoryRequest.metadata":       metadataBound("editMemory metadata"),
	"schemas/EditMemoryRequest.metadata.<key>": metadataValueBound("editMemory metadata"),
	"schemas/EditMemoryRequest.subject":        lineBound("rules.NormalizeSubject"),
	"schemas/EditMemoryRequest.tags":           tagsBound("editMemory tags"),
	"schemas/EditMemoryRequest.tags[]":         tagItemBound("editMemory tags"),
	"schemas/EditMemoryRequest.type":           labelBound("editMemory type"),

	"schemas/JWK": {MaxProps: n(keys.MaxJWKMembers), Unit: keysUnit, Source: "keys.MaxJWKMembers"},

	"schemas/OfferedCursor.channel": nameBound("offered cursor channel"),
	"schemas/OfferedCursor.seq":     seqBound("offered cursor seq"),

	"schemas/OpenSessionRequest.cursors":      arrayBound("openSession cursors"),
	"schemas/OpenSessionRequest.hint":         nameBound("session hint"),
	"schemas/OpenSessionRequest.resume_token": {MinLength: sessions.ResumeTokenLen, MaxLength: n(sessions.ResumeTokenLen), Pattern: sessions.ResumeTokenPattern, Unit: codePoints, Source: "sessions.ResumeTokenLen, ResumeTokenPattern"},

	"schemas/ReceiveRequest.ack":        tokenBound("delivery.Receive ack"),
	"schemas/ReceiveRequest.channels":   arrayBound("receive channels"),
	"schemas/ReceiveRequest.channels[]": nameBound("receive channel"),
	"schemas/ReceiveRequest.count":      countBound(core.ReceiveCountCeiling, "receive_max_count", "core.ReceiveCountCeiling"),

	"schemas/RegisterRequest.enrollment_token": tokenBound("identities.Register"),
	"schemas/RegisterRequest.identity":         nameBound("registered identity"),

	"schemas/RenameChannelRequest.name": nameBound("channel name"),

	"schemas/SendRequest.content":        contentBound("send content"),
	"schemas/SendRequest.metadata":       metadataBound("send metadata"),
	"schemas/SendRequest.metadata.<key>": metadataValueBound("send metadata"),
	"schemas/SendRequest.reply_to":       idBound("send reply_to"),
	"schemas/SendRequest.session":        tokenBound("sessions.Require"),
	"schemas/SendRequest.subject":        lineBound("rules.NormalizeSubject"),
	"schemas/SendRequest.tags":           tagsBound("send tags"),
	"schemas/SendRequest.tags[]":         tagItemBound("send tags"),
	"schemas/SendRequest.type":           labelBound("send type"),

	"schemas/SetAgentStatusRequest.problem": lineBound("agent status problem"),
	"schemas/SetAgentStatusRequest.tag":     labelBound("agent status tag"),
	"schemas/SetAgentStatusRequest.text":    lineBound("agent status text"),

	"schemas/TagPatterns.patterns":   patternsBound("tag subscription patterns"),
	"schemas/TagPatterns.patterns[]": patternItemBound("tag subscription patterns"),

	"schemas/TaskCreateRequest.after":          idBound("task after"),
	"schemas/TaskCreateRequest.before":         idBound("task before"),
	"schemas/TaskCreateRequest.blocked_by":     blockersBound("task blocked_by"),
	"schemas/TaskCreateRequest.blocked_by[]":   idBound("task blocker id"),
	"schemas/TaskCreateRequest.description":    contentBound("task description"),
	"schemas/TaskCreateRequest.metadata":       metadataBound("task metadata"),
	"schemas/TaskCreateRequest.metadata.<key>": metadataValueBound("task metadata"),
	"schemas/TaskCreateRequest.parent":         idBound("task parent"),
	"schemas/TaskCreateRequest.subject":        {MinLength: 1, MaxLength: n(tasks.MaxSubjectRunes), Unit: codePoints, Source: "tasks.MaxSubjectRunes; ruling 3"},

	"schemas/TaskPatch.add_blocked_by":      blockersBound("task patch add_blocked_by"),
	"schemas/TaskPatch.add_blocked_by[]":    idBound("task blocker id"),
	"schemas/TaskPatch.after":               idBound("task after"),
	"schemas/TaskPatch.before":              idBound("task before"),
	"schemas/TaskPatch.description":         contentBound("task description"),
	"schemas/TaskPatch.leased_until":        idBound("task leased_until"),
	"schemas/TaskPatch.metadata":            metadataBound("task patch metadata"),
	"schemas/TaskPatch.metadata.<key>":      metadataValueBound("task patch metadata"),
	"schemas/TaskPatch.owner":               nameBound("task owner"),
	"schemas/TaskPatch.parent":              idBound("task parent"),
	"schemas/TaskPatch.remove_blocked_by":   blockersBound("task patch remove_blocked_by"),
	"schemas/TaskPatch.remove_blocked_by[]": idBound("task blocker id"),
	"schemas/TaskPatch.status":              labelBound("task status"),
	"schemas/TaskPatch.subject":             {MaxLength: n(tasks.MaxSubjectRunes), Unit: codePoints, Source: "tasks.MaxSubjectRunes; ruling 3"},

	"schemas/TokenRequest.actor_token":           jwtBound("actor_token"),
	"schemas/TokenRequest.actor_token_type":      oauthBound("actor_token_type"),
	"schemas/TokenRequest.audience":              oauthBound("audience"),
	"schemas/TokenRequest.client_assertion":      jwtBound("client_assertion"),
	"schemas/TokenRequest.client_assertion_type": oauthBound("client_assertion_type"),
	"schemas/TokenRequest.client_id":             {MaxLength: n(store.MaxNameBytes), Unit: bytesUnit, Source: "store.NameRule; an identity name"},
	"schemas/TokenRequest.grant_type":            oauthBound("grant_type"),
	"schemas/TokenRequest.requested_token_type":  oauthBound("requested_token_type"),
	"schemas/TokenRequest.resource":              oauthBound("resource"),
	"schemas/TokenRequest.scope":                 oauthBound("scope"),
	"schemas/TokenRequest.subject_token":         jwtBound("subject_token"),
	"schemas/TokenRequest.subject_token_type":    oauthBound("subject_token_type"),
}

func u64(p *uint64) string {
	if p == nil {
		return "absent"
	}
	return fmt.Sprint(*p)
}

func fl(p *float64) string {
	if p == nil {
		return "absent"
	}
	return fmt.Sprintf("%v", *p)
}

// diffBound names every member of b the spec's schema states differently.
func diffBound(b bound, l leaf) []string {
	s := l.schema
	var out []string
	chk := func(name, want, got string) {
		if want != got {
			out = append(out, fmt.Sprintf("%s: spec lacks or differs: want %s, spec has %s", name, want, got))
		}
	}
	var ml *uint64
	if b.MaxLength != nil {
		v := uint64(*b.MaxLength)
		ml = &v
	}
	chk("maxLength", u64(ml), u64(s.MaxLength))
	chk("minLength", fmt.Sprint(b.MinLength), fmt.Sprint(s.MinLength))
	chk("pattern", fmt.Sprintf("%q", b.Pattern), fmt.Sprintf("%q", s.Pattern))
	chk("minimum", fl(b.Min), fl(s.Min))
	chk("maximum", fl(b.Max), fl(s.Max))
	chk("format", b.Format, s.Format)
	var mi *uint64
	if b.MaxItems != nil {
		v := uint64(*b.MaxItems)
		mi = &v
	}
	chk("maxItems", u64(mi), u64(s.MaxItems))
	chk("minItems", fmt.Sprint(b.MinItems), fmt.Sprint(s.MinItems))
	var mp *uint64
	if b.MaxProps != nil {
		v := uint64(*b.MaxProps)
		mp = &v
	}
	chk("maxProperties", u64(mp), u64(s.MaxProps))
	if b.Unit != noUnit && !strings.Contains(l.desc, string(b.Unit)) {
		out = append(out, fmt.Sprintf("description lacks the unit %q", b.Unit))
	}
	if b.Setting != "" && !strings.Contains(l.desc, b.Setting) {
		out = append(out, fmt.Sprintf("description lacks the setting %q", b.Setting))
	}
	return out
}

func TestSpecBounds(t *testing.T) {
	leaves, _ := walkRequests(Spec())
	keysSorted := make([]string, 0, len(leaves))
	for k := range leaves {
		keysSorted = append(keysSorted, k)
	}
	sort.Strings(keysSorted)

	for _, k := range keysSorted {
		l := leaves[k]
		t.Run(k, func(t *testing.T) {
			b, ok := bounds[k]
			if !ok {
				t.Fatalf("unlisted field (%s): add a row to bounds", l.kind)
			}
			for _, d := range diffBound(b, l) {
				t.Error(d)
			}
		})
	}

	t.Run("coverage", func(t *testing.T) {
		for _, k := range keysSorted {
			if _, ok := bounds[k]; !ok {
				t.Errorf("%s (%s) has no row", k, leaves[k].kind)
			}
		}
	})

	t.Run("stale", func(t *testing.T) {
		for k := range bounds {
			if _, ok := leaves[k]; !ok {
				t.Errorf("row %q matches no bounded field of the spec", k)
			}
		}
	})

	// A format: int32 keeps the generated Go type only with x-go-type: int.
	t.Run("int32_types", func(t *testing.T) {
		for _, k := range keysSorted {
			s := leaves[k].schema
			if s.Format != "int32" {
				continue
			}
			if got, _ := s.Extensions["x-go-type"].(string); got != "int" {
				t.Errorf("%s: format int32 needs x-go-type: int, has %v", k, s.Extensions["x-go-type"])
			}
		}
	})

	// Ruling 5: the request side keeps the six enums it had; the core-owned
	// vocabularies (status tags, task statuses, token grant types) stay
	// strings so the core's own messages are what a client sees.
	t.Run("enums", func(t *testing.T) {
		_, enums := walkRequests(Spec())
		sort.Strings(enums)
		want := []string{
			"operations/adminReset/query/scope",
			"operations/search/query/mode",
			"schemas/ACLEntry.permissions[]",
			"schemas/CreateChannelRequest.kind",
			"schemas/DoneScopeRequest.retire",
			"schemas/SubscribeRequest.from",
		}
		if fmt.Sprint(enums) != fmt.Sprint(want) {
			t.Errorf("request enums %v, want %v (ruling 5)", enums, want)
		}
	})
}

// problemDetail reads the detail of a problem+json body.
func problemDetail(t *testing.T, body []byte) (code, detail string) {
	t.Helper()
	var p struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("problem body %q: %v", body, err)
	}
	return p.Code, p.Detail
}

func cjk(n int) string { return strings.Repeat("日", n) }

// TestValidatorCountsCodePoints: a query string is validated decoded, in code
// points, so 128 three-byte code points pass kin's maxLength 128; the core's
// name rule (bytes) refuses it with validation afterwards.
func TestValidatorCountsCodePoints(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("alice", false)
	code, body := statusReq(t, e, "alice", http.MethodGet, "/v1/search?q=hello&channel="+url.QueryEscape(cjk(128)), "", "")
	if code != 400 {
		t.Fatalf("status %d: %s", code, body)
	}
	_, detail := problemDetail(t, body)
	if strings.Contains(detail, "maxLength: got") {
		t.Errorf("the validator refused 128 code points: %s", detail)
	}
	code, body = statusReq(t, e, "alice", http.MethodGet, "/v1/search?q=hello&channel="+url.QueryEscape(cjk(129)), "", "")
	if code != 400 {
		t.Fatalf("status %d: %s", code, body)
	}
	if _, detail = problemDetail(t, body); !strings.Contains(detail, "maxLength: got 129, want 128") {
		t.Errorf("129 code points: detail %q lacks the validator's maxLength refusal", detail)
	}
}

// TestValidatorCountsEncodedPath: kin validates the percent-encoded path
// segment (ruling 15), so ChannelParam is 3 * 128 characters.
func TestValidatorCountsEncodedPath(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("alice", false)
	long := cjk(128) // 384 bytes, 1152 encoded characters
	if got := len(url.PathEscape(long)); got != 1152 {
		t.Fatalf("encoded length %d", got)
	}
	code, body := statusReq(t, e, "alice", http.MethodGet, "/v1/channels/"+url.PathEscape(long)+"/acl", "", "")
	if code != 400 {
		t.Fatalf("status %d: %s", code, body)
	}
	if _, detail := problemDetail(t, body); !strings.Contains(detail, "want 384") || !strings.Contains(detail, "maxLength") {
		t.Errorf("detail %q lacks the validator's maxLength refusal", detail)
	}
	// 128 bytes that encode to exactly 384 characters: the validator passes
	// it and the core answers (the channel does not exist).
	name := cjk(42) + "%%"
	if len(name) != 128 || len(url.PathEscape(name)) != 384 {
		t.Fatalf("fixture: %d bytes, %d encoded", len(name), len(url.PathEscape(name)))
	}
	code, body = statusReq(t, e, "alice", http.MethodGet, "/v1/channels/"+url.PathEscape(name)+"/acl", "", "")
	if strings.Contains(string(body), "maxLength: got") {
		t.Errorf("the validator refused 384 encoded characters (status %d): %s", code, body)
	}
}

// TestInt64OverflowRefused pins ruling 6: kin admits MaxInt64 and the strict
// handler's decode refuses 2^63.
func TestInt64OverflowRefused(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("alice", false)
	send := func(replyTo string) (int, []byte) {
		return statusReq(t, e, "alice", http.MethodPost, "/v1/channels/nochan/messages", "k-int64-"+replyTo[len(replyTo)-1:],
			`{"session":"s","content":"x","reply_to":`+replyTo+`}`)
	}
	code, body := send("9223372036854775808")
	if code != 400 {
		t.Fatalf("2^63: status %d: %s", code, body)
	}
	if c, _ := problemDetail(t, body); c != "validation" {
		t.Errorf("2^63: code %q: %s", c, body)
	}
	code, body = send("9223372036854775807")
	if code == 400 {
		_, detail := problemDetail(t, body)
		if strings.Contains(detail, "number must be at most") || strings.Contains(detail, "cannot unmarshal") {
			t.Errorf("MaxInt64 was refused before the core: %s", body)
		}
	}
}

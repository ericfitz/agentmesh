package server

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/bus/remote"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// The wire round-trip harness (issue #29): every member of a generated type
// is filled with a distinct non-zero value, carried through the client's
// converter and the server's converter, and compared. A member one side drops
// or swaps shows as a diff line. Later tasks append pairs and exceptions.

// pair is one generated type and the domain type the two converters carry it
// to and from.
type pair struct {
	name    string                                     // the generated type's name: the subtest name
	gen     reflect.Type                               // the generated struct (or ScopeList-style wrapper)
	bus     reflect.Type                               // the domain struct, slice or scalar
	genTrip func(reflect.Value) (reflect.Value, error) // gen -> bus -> gen
	busTrip func(reflect.Value) (reflect.Value, error) // bus -> gen -> bus
}

// pairOf builds a pair from the client's converter (fromGen) and the server's
// (toGen).
func pairOf[G, B any](name string, fromGen func(G) (B, error), toGen func(B) (G, error)) pair {
	return pair{
		name: name,
		gen:  reflect.TypeFor[G](),
		bus:  reflect.TypeFor[B](),
		genTrip: func(v reflect.Value) (reflect.Value, error) {
			b, err := fromGen(v.Interface().(G))
			if err != nil {
				return reflect.Value{}, err
			}
			g, err := toGen(b)
			return reflect.ValueOf(&g).Elem(), err
		},
		busTrip: func(v reflect.Value) (reflect.Value, error) {
			g, err := toGen(v.Interface().(B))
			if err != nil {
				return reflect.Value{}, err
			}
			b, err := fromGen(g)
			return reflect.ValueOf(&b).Elem(), err
		},
	}
}

// ok adapts a converter that cannot fail.
func ok[I, O any](f func(I) O) func(I) (O, error) {
	return func(i I) (O, error) { return f(i), nil }
}

var pairs = []pair{
	pairOf("Message", remote.FromGenMessage, ok(toGenMessage)),
	pairOf("ACLEntry", ok(remote.FromGenACLEntry), ok(aclEntryToGen)),
	pairOf("Task", ok(remote.FromGenTask), ok(taskToGen)),
	pairOf("TaskSummary", ok(remote.FromGenTaskSummary), ok(taskSummaryToGen)),
	pairOf("TaskUpdateResult", ok(remote.FromGenTaskResult), ok(taskResultToGen)),
	pairOf("Health", remote.FromGenHealth, ok(healthToGen)),
	pairOf("Usage", remote.FromGenUsage, ok(usageToGen)),
	pairOf("ChannelInfo", ok(remote.FromGenChannelInfo), ok(channelInfoToGen)),
	pairOf("Scope", remote.FromGenScope, ok(scopeToGen)),
	pairOf("Bridge", remote.FromGenBridge, ok(bridgeToGen)),
	pairOf("SigningKey", remote.FromGenSigningKey, ok(signingKeyToGen)),
	pairOf("AgentStatus", ok(remote.FromGenAgentStatus), ok(agentStatusToGen)),
	pairOf("OpenSessionRequestObject", ok(openSessionInput), ok(remote.OpenSessionRequest)),
	pairOf("Session", ok(remote.FromGenSession), ok(sessionToGen)),
	pairOf("CloseSessionRequestObject", ok(closeSessionInput), ok(remote.CloseSessionRequest)),
	pairOf("ReceiveRequestObject", ok(receiveInput), ok(remote.ReceiveRequest)),
	pairOf("ReceiveResult", remote.FromGenReceiveResult, ok(receiveResultToGen)),
	pairOf("WatchRequestObject", watchInput, ok(remote.WatchRequest)),
	pairOf("Wake", ok(remote.FromGenWake), ok(wakeToGen)),
	pairOf("PeekRequestObject", ok(peekInput), ok(remote.PeekRequest)),
	pairOf("Peek", ok(remote.FromGenPeek), ok(peekToGen)),
	pairOf("Identity", remote.FromGenIdentity, ok(identityToGen)),
	pairOf("SetAgentStatusRequestObject", ok(setAgentStatusInput), ok(remote.SetAgentStatusRequest)),
	pairOf("AgentStatusEntry", remote.FromGenAgentStatusEntry, ok(agentStatusEntryToGen)),
	pairOf("CreateChannelRequestObject", ok(createChannelInput), ok(remote.CreateChannelRequest)),
	pairOf("Channel", ok(remote.FromGenChannel), ok(channelToGen)),
	pairOf("DeleteChannelRequestObject", ok(deleteChannelInput), ok(remote.DeleteChannelRequest)),
	pairOf("RenameChannelRequestObject", ok(renameChannelInput), ok(remote.RenameChannelRequest)),
	pairOf("SetACLRequestObject", ok(setACLInput), ok(remote.SetACLRequest)),
	pairOf("SubscribeRequestObject", ok(subscribeInput), ok(remote.SubscribeRequest)),
	pairOf("UnsubscribeRequestObject", ok(unsubscribeInput), ok(remote.UnsubscribeRequest)),
	pairOf("SubscribeTagsRequestObject", ok(subscribeTagsInput), ok(remote.SubscribeTagsRequest)),
	pairOf("UnsubscribeTagsRequestObject", ok(unsubscribeTagsInput), ok(remote.UnsubscribeTagsRequest)),
	pairOf("SendMessageRequestObject", sendInput, ok(remote.SendMessageRequest)),
	pairOf("SendResult", ok(remote.FromGenSendResult), ok(sendResultToGen)),
	pairOf("HistoryRequestObject", ok(historyInput), ok(remote.HistoryRequest)),
	pairOf("SearchRequestObject", ok(searchInput), ok(remote.SearchRequest)),
	pairOf("SearchResult", remote.FromGenSearchResult, ok(searchResultToGen)),
	pairOf("EditMemoryRequestObject", editMemoryInput, ok(remote.EditMemoryRequest)),
	pairOf("EditResult", ok(remote.FromGenEditResult), ok(editResultToGen)),
	pairOf("DeleteMemoryRequestObject", ok(deleteMemoryInput), ok(remote.DeleteMemoryRequest)),
	pairOf("CreateTaskRequestObject", createTaskInput, ok(remote.CreateTaskRequest)),
	pairOf("ListTasksRequestObject", ok(listTasksInput), ok(remote.ListTasksRequest)),
	pairOf("UpdateTaskRequestObject", updateTaskInput, ok(remote.UpdateTaskRequest)),
	pairOf("ClaimTaskRequestObject", ok(claimTaskInput), ok(remote.ClaimTaskRequest)),
	pairOf("ReleaseTaskRequestObject", ok(releaseTaskInput), ok(remote.ReleaseTaskRequest)),
	pairOf("Status", ok(remote.FromGenStatus), ok(statusToGen)),
	pairOf("AdminResetRequestObject", ok(adminResetInput), ok(remote.AdminResetRequest)),
	pairOf("ResetCredentialRequestObject", ok(resetCredentialInput), ok(remote.ResetCredentialRequest)),
	pairOf("CredentialReset", ok(remote.FromGenCredentialReset), ok(credentialResetToGen)),
	pairOf("CreateIdentityByEmailRequestObject", ok(createIdentityByEmailInput), ok(remote.CreateIdentityByEmailRequest)),
	pairOf("HumanIdentity", ok(remote.FromGenHumanIdentity), ok(humanIdentityToGen)),
	pairOf("CreateScopeRequestObject", ok(createScopeInput), ok(remote.CreateScopeRequest)),
	pairOf("DoneScopeRequestObject", ok(doneScopeInput), ok(remote.DoneScopeRequest)),
	pairOf("ScopeList", remote.FromGenScopeList, ok(scopeListToGen)),
	pairOf("CreateAgentIdentityRequestObject", ok(createAgentIdentityInput), ok(remote.CreateAgentIdentityRequest)),
	pairOf("AgentIdentity", ok(remote.FromGenAgentIdentity), ok(agentIdentityToGen)),
	pairOf("CreateBridgeRequestObject", ok(createBridgeInput), ok(remote.CreateBridgeRequest)),
	pairOf("BridgeCreated", remote.FromGenBridgeCreated, ok(bridgeCreatedToGen)),
	pairOf("BridgeList", remote.FromGenBridgeList, ok(bridgeListToGen)),
	pairOf("RemoveBridgeRequestObject", ok(removeBridgeInput), ok(remote.RemoveBridgeRequest)),
	pairOf("SigningKeyList", remote.FromGenSigningKeyList, ok(signingKeyListToGen)),
	pairOf("RotateSigningKeyRequestObject", ok(rotateSigningKeyInput), ok(remote.RotateSigningKeyRequest)),
	pairOf("SigningKeyRotation", remote.FromGenSigningKeyRotation, ok(signingKeyRotationToGen)),
}

// exception names a member a converter pair may not carry, with the reason.
// Keys are "gen:<Pair>.<path>" or "bus:<Pair>.<path>" (the side whose trip
// shows the diff), or a type name.
type exception struct {
	Type   reflect.Type // nil for a member-level entry; set for a whole-type entry
	Fields []string
	Reason string
}

var exceptions = map[string]exception{
	"Problem": {Type: reflect.TypeFor[gen.Problem](), Fields: []string{"Code", "Detail", "Instance", "Retryable", "Status", "Title", "Type"},
		Reason: "errors cross as RFC 9457 problems: WriteProblem writes (internal/server), errorOf reads (internal/bus/remote, function errorOf)"},
	"OAuthError": {Type: reflect.TypeFor[gen.OAuthError](), Fields: []string{"Error", "ErrorDescription"},
		Reason: "the token endpoint answers the RFC 6749 error body (internal/server/oauth.go); internal/bus/remote/auth.go reads it (function oauthErrorOf), not a Bus domain type"},
	"Discovery": {Type: reflect.TypeFor[gen.Discovery](), Fields: []string{"ApiVersions", "AuthMethods", "AuthorizationServer", "Capabilities", "Issuers", "OpenidConfiguration", "ProtocolVersion", "ServerVersion"},
		Reason: authReason},
	"AuthMethod": {Type: reflect.TypeFor[gen.AuthMethod](), Fields: []string{"BearerFormat", "Name", "Scheme", "Type"}, Reason: authReason},
	"WellKnown":  {Type: reflect.TypeFor[gen.WellKnown](), Fields: []string{"Discover"}, Reason: authReason},
	"AuthorizationServerMetadata": {Type: reflect.TypeFor[gen.AuthorizationServerMetadata](),
		Fields: []string{"GrantTypesSupported", "Issuer", "JwksUri", "ResponseTypesSupported", "TokenEndpoint", "TokenEndpointAuthMethodsSupported", "TokenEndpointAuthSigningAlgValuesSupported"},
		Reason: authReason},
	"JWKS":                  {Type: reflect.TypeFor[gen.JWKS](), Fields: []string{"Keys"}, Reason: authReason},
	"AccessToken":           {Type: reflect.TypeFor[gen.AccessToken](), Fields: []string{"AccessToken", "ExpiresIn", "IssuedTokenType", "TokenType"}, Reason: authReason},
	"Registration":          {Type: reflect.TypeFor[gen.Registration](), Fields: []string{"Algorithm", "Created", "Identity", "Kid"}, Reason: authReason},
	"RegisterRequest":       {Type: reflect.TypeFor[gen.RegisterRequest](), Fields: []string{"EnrollmentToken", "Identity", "PublicKeyJwk"}, Reason: authReason},
	"RegisterRequestObject": {Type: reflect.TypeFor[gen.RegisterRequestObject](), Fields: []string{"Body"}, Reason: authReason},
	"TokenRequestObject":    {Type: reflect.TypeFor[gen.TokenRequestObject](), Fields: []string{"Body"}, Reason: authReason},
	"TokenRequest": {Type: reflect.TypeFor[gen.TokenRequest](),
		Fields: []string{"ActorToken", "ActorTokenType", "Audience", "ClientAssertion", "ClientAssertionType", "ClientId", "GrantType", "RequestedTokenType", "Resource", "Scope", "SubjectToken", "SubjectTokenType"},
		Reason: "the token endpoint's form body (the body struct of TokenRequestObject): internal/bus/remote/auth.go builds it (TokenFormdataRequestBody, in the functions Token and TokenExchange), internal/server/auth_handlers.go reads it; not a Bus domain type"},
	"GetTaskRequestObject":             {Type: reflect.TypeFor[gen.GetTaskRequestObject](), Fields: []string{"Id"}, Reason: pathReason},
	"GetMemoryRequestObject":           {Type: reflect.TypeFor[gen.GetMemoryRequestObject](), Fields: []string{"Id"}, Reason: pathReason},
	"ListMemoryRevisionsRequestObject": {Type: reflect.TypeFor[gen.ListMemoryRevisionsRequestObject](), Fields: []string{"Id"}, Reason: pathReason},
	"GetScopeRequestObject":            {Type: reflect.TypeFor[gen.GetScopeRequestObject](), Fields: []string{"Scope"}, Reason: pathReason},
	"GetBridgeRequestObject":           {Type: reflect.TypeFor[gen.GetBridgeRequestObject](), Fields: []string{"Channel"}, Reason: pathReason},
	"GetACLRequestObject":              {Type: reflect.TypeFor[gen.GetACLRequestObject](), Fields: []string{"Channel"}, Reason: pathReason},
	"AgentStatusHistoryRequestObject":  {Type: reflect.TypeFor[gen.AgentStatusHistoryRequestObject](), Fields: []string{"Identity"}, Reason: pathReason},
}

const (
	authReason = "discovery and authentication documents: internal/server (discovery.go, auth_handlers.go) writes them, internal/bus/remote/auth.go (register, token exchange) reads or builds them through the generated client; not Bus domain types"
	pathReason = "the path parameter alone: the Bus method takes it as a scalar and the client passes it as given"
)

// plumbingPatterns are the generated names that are transport plumbing, not
// wire models. A name matches when it has the prefix or the suffix.
var plumbingPatterns = []struct{ Prefix, Suffix, Reason string }{
	{Suffix: "Response", Reason: "typed client and strict-server response wrappers (also *JSONResponse)"},
	{Suffix: "Options", Reason: "generated server options"},
	{Suffix: "ParamError", Reason: "generated parameter-binding errors (OAuthError is a model and stays enumerated)"},
	{Suffix: "HeaderError", Reason: "generated parameter-binding errors"},
	{Suffix: "FormatError", Reason: "generated parameter-binding errors"},
	{Prefix: "Client", Reason: "the generated client and its options"},
	{Prefix: "strictHandler", Reason: "the strict server adapter"},
	{Prefix: "ServerInterfaceWrapper", Reason: "the generated router wrapper"},
}

func isPlumbing(name string) bool {
	for _, p := range plumbingPatterns {
		if (p.Prefix != "" && strings.HasPrefix(name, p.Prefix)) || (p.Suffix != "" && strings.HasSuffix(name, p.Suffix)) {
			return true
		}
	}
	return false
}

// genStructs parses every non-test Go file of the generated package
// (internal/gen) and returns every struct type that is not plumbing, with its
// exported field names.
func genStructs(t *testing.T) map[string][]string {
	t.Helper()
	paths, err := filepath.Glob("../gen/*.go")
	if err != nil {
		t.Fatalf("glob internal/gen: %v", err)
	}
	out := map[string][]string{}
	fset := token.NewFileSet()
	var decls []ast.Decl
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		decls = append(decls, f.Decls...)
	}
	for _, d := range decls {
		gd, isGen := d.(*ast.GenDecl)
		if !isGen || gd.Tok != token.TYPE {
			continue
		}
		for _, sp := range gd.Specs {
			ts := sp.(*ast.TypeSpec)
			st, isStruct := ts.Type.(*ast.StructType)
			if !isStruct {
				continue
			}
			if isPlumbing(ts.Name.Name) {
				doc := gd.Doc.Text()
				if ts.Doc != nil {
					doc += ts.Doc.Text()
				}
				if strings.Contains(doc, "defines model for") || strings.Contains(doc, "defines parameters for") {
					t.Errorf("generated type %s is a model but matches a plumbing pattern: narrow plumbingPatterns", ts.Name.Name)
				}
				continue
			}
			fields := []string{}
			for _, fl := range st.Fields.List {
				for _, n := range fl.Names {
					if n.IsExported() {
						fields = append(fields, n.Name)
					}
				}
			}
			out[ts.Name.Name] = fields
		}
	}
	return out
}

// reachable returns the names of the gen struct types reachable from types
// through fields, pointers, slices, arrays and maps.
func reachable(types ...reflect.Type) map[string]bool {
	seen := map[reflect.Type]bool{}
	out := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(ty reflect.Type) {
		if seen[ty] {
			return
		}
		seen[ty] = true
		switch ty.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(ty.Elem())
		case reflect.Map:
			walk(ty.Elem())
		case reflect.Struct:
			if ty.PkgPath() == reflect.TypeFor[gen.Problem]().PkgPath() {
				out[ty.Name()] = true
			}
			for i := 0; i < ty.NumField(); i++ {
				if ty.Field(i).IsExported() {
					walk(ty.Field(i).Type)
				}
			}
		}
	}
	for _, ty := range types {
		walk(ty)
	}
	return out
}

// enumValues holds the value fill gives a member whose converter validates
// it, keyed by member path ("Health.Store.Engine") or by reflect.Type.String()
// ("gen.HealthTier"). A member path wins over the type.
var enumValues = map[string]any{
	"gen.MessageSenderKind":     gen.MessageSenderKind(bus.IdentityAgent),
	"bus.IdentityKind":          bus.IdentityHuman,
	"gen.IdentityKind":          gen.IdentityKind(bus.IdentityAgent),
	"gen.AgentStatusEntryKind":  gen.AgentStatusEntryKind(bus.IdentityHuman),
	"gen.HealthStatus":          gen.HealthStatusOk,
	"bus.HealthStatus":          bus.HealthOK,
	"gen.HealthTier":            gen.HealthTier(bus.TierAdmin),
	"bus.HealthTier":            bus.TierAdmin,
	"Health.Store.Engine":       "sqlite",
	"gen.HealthEmbeddingsState": gen.HealthEmbeddingsState(bus.EmbeddingsOK),
	"bus.EmbeddingState":        bus.EmbeddingsOK,
	"gen.HealthMaintenanceLock": gen.HealthMaintenanceLock(bus.LockHeld),
	"bus.MaintenanceLock":       bus.LockHeld,
	"gen.UsageTier":             gen.UsageTier(bus.PressureSoft),
	"bus.PressureTier":          bus.PressureSoft,
	"gen.ScopeState":            gen.ScopeState(bus.ScopeOpen),
	"bus.ScopeState":            bus.ScopeOpen,
	"gen.ScopeRetire":           gen.ScopeRetire(bus.RetireNormal),
	"bus.RetireMode":            bus.RetireNormal,
	"gen.BridgeState":           gen.BridgeState(bus.BridgeCreating),
	"bus.BridgeState":           bus.BridgeCreating,
}

// The bus side of a signing key carries its state, provider and algorithm as
// plain strings, so they are keyed by member path, one set per place a key
// sits in a filled value.
func init() {
	for _, prefix := range []string{
		"SigningKey", "SigningKeyList.Keys[0]", "SigningKeyList[0]", "SigningKeyRotation.Active", "SigningKeyRotation.Previous",
	} {
		enumValues[prefix+".State"] = "active"
		enumValues[prefix+".Provider"] = "store"
		enumValues[prefix+".Algorithm"] = "EdDSA"
	}
}

type counter struct{ n int64 }

func (c *counter) next() int64 { c.n++; return 1000 + c.n }

// fill sets every member of v non-zero, so a member a converter drops or
// swaps shows as a diff. Every enumValues key it consults is recorded in used.
func fill(t *testing.T, v reflect.Value, path string, c *counter, used map[string]bool) {
	t.Helper()
	ty := v.Type()
	if e, found := lookupEnum(path, ty, used); found {
		ev := reflect.ValueOf(e)
		if !ev.Type().ConvertibleTo(ty) {
			t.Fatalf("enumValues entry for %s has type %s, not convertible to %s", path, ev.Type(), ty)
		}
		v.Set(ev.Convert(ty))
		return
	}
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(c.next())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(c.next()))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(c.next()))
	case reflect.String:
		v.SetString(path)
	case reflect.Pointer:
		v.Set(reflect.New(ty.Elem()))
		fill(t, v.Elem(), path, c, used)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(ty, 1, 1))
		fill(t, v.Index(0), path+"[0]", c, used)
	case reflect.Map:
		if ty.Key().Kind() != reflect.String {
			t.Fatalf("unsupported map key kind at %s", path)
		}
		m := reflect.MakeMap(ty)
		val := reflect.New(ty.Elem()).Elem()
		fill(t, val, path+".k", c, used)
		k := reflect.New(ty.Key()).Elem()
		k.SetString(path + ".k")
		m.SetMapIndex(k, val)
		v.Set(m)
	case reflect.Struct:
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			if !f.IsExported() {
				continue
			}
			fill(t, v.Field(i), path+"."+f.Name, c, used)
		}
	default:
		t.Fatalf("unsupported kind %s at %s", v.Kind(), path)
	}
}

// lookupEnum finds the enumValues entry for a member: its path first, then its
// type. A hit is recorded in used.
func lookupEnum(path string, ty reflect.Type, used map[string]bool) (any, bool) {
	if ty.Kind() == reflect.Pointer {
		return nil, false // the lookup happens at the element
	}
	if e, found := enumValues[path]; found {
		used[path] = true
		return e, true
	}
	if e, found := enumValues[ty.String()]; found {
		used[ty.String()] = true
		return e, true
	}
	return nil, false
}

// diff walks want and got (the same Go type) in parallel and returns one
// "path: want X, got Y" line per difference.
func diff(path string, want, got reflect.Value) []string {
	line := func(w, g any) []string { return []string{fmt.Sprintf("%s: want %v, got %v", path, w, g)} }
	switch want.Kind() {
	case reflect.Pointer:
		if want.IsNil() != got.IsNil() {
			return line(describeNil(want), describeNil(got))
		}
		if want.IsNil() {
			return nil
		}
		return diff(path, want.Elem(), got.Elem())
	case reflect.Slice:
		if want.IsNil() != got.IsNil() || want.Len() != got.Len() {
			return line(fmt.Sprintf("len %d nil=%v", want.Len(), want.IsNil()), fmt.Sprintf("len %d nil=%v", got.Len(), got.IsNil()))
		}
		var out []string
		for i := 0; i < want.Len(); i++ {
			out = append(out, diff(fmt.Sprintf("%s[%d]", path, i), want.Index(i), got.Index(i))...)
		}
		return out
	case reflect.Map:
		var out []string
		keys := want.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		for _, k := range keys {
			g := got.MapIndex(k)
			if !g.IsValid() {
				out = append(out, fmt.Sprintf("%s.%v: want present, got missing", path, k))
				continue
			}
			out = append(out, diff(fmt.Sprintf("%s.%v", path, k), want.MapIndex(k), g)...)
		}
		if got.Len() > want.Len() {
			out = append(out, fmt.Sprintf("%s: want %d entries, got %d", path, want.Len(), got.Len()))
		}
		return out
	case reflect.Struct:
		var out []string
		for i := 0; i < want.NumField(); i++ {
			f := want.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			out = append(out, diff(path+"."+f.Name, want.Field(i), got.Field(i))...)
		}
		return out
	}
	if !reflect.DeepEqual(want.Interface(), got.Interface()) {
		return line(want.Interface(), got.Interface())
	}
	return nil
}

func describeNil(v reflect.Value) string {
	if v.IsNil() {
		return "nil"
	}
	return "non-nil"
}

// linePath is the path of a diff line.
func linePath(line string) string {
	p, _, _ := strings.Cut(line, ": want ")
	if i := strings.Index(p, " "); i >= 0 {
		p = p[:i]
	}
	return p
}

func TestWireRoundTrip(t *testing.T) {
	used := map[string]bool{}
	hit := map[string]bool{}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			check := func(side string, ty reflect.Type, trip func(reflect.Value) (reflect.Value, error)) {
				want := reflect.New(ty).Elem()
				fill(t, want, p.name, &counter{}, used)
				got, err := trip(want)
				if err != nil {
					t.Fatalf("%s: %s side trip: %v", p.name, side, err)
				}
				for _, l := range diff(p.name, want, got) {
					key := side + ":" + linePath(l)
					if _, excepted := exceptions[key]; excepted {
						hit[key] = true
						continue
					}
					t.Errorf("%s side: %s", side, l)
				}
			}
			check("gen", p.gen, p.genTrip)
			check("bus", p.bus, p.busTrip)
		})
	}
	t.Run("enums", func(t *testing.T) {
		for k := range enumValues {
			if !used[k] {
				t.Errorf("enumValues[%q] was never consulted", k)
			}
		}
	})
	structs := genStructs(t)
	t.Run("coverage", func(t *testing.T) {
		if len(structs) < 120 {
			t.Fatalf("only %d generated struct types enumerated (want at least 120): the generator's output changed; the enumeration is blind", len(structs))
		}
		var pairGens []reflect.Type
		for _, p := range pairs {
			pairGens = append(pairGens, p.gen)
		}
		// A pair covers every struct reachable from it (fill sets them all).
		// An exception covers only its own root: a struct nested under an
		// exception root needs its own entry (issue #29 review, Finding 7).
		covered := reachable(pairGens...)
		for _, e := range exceptions {
			if e.Type != nil {
				covered[e.Type.Name()] = true
			}
		}
		var missing []string
		for name, fields := range structs {
			if len(fields) == 0 || covered[name] {
				continue
			}
			missing = append(missing, name)
		}
		sort.Strings(missing)
		for _, name := range missing {
			t.Errorf("generated type %s is neither paired nor excepted", name)
		}
	})
	t.Run("exceptions", func(t *testing.T) {
		var paired []reflect.Type
		for _, p := range pairs {
			paired = append(paired, p.gen)
		}
		pairCovered := reachable(paired...)
		for key, e := range exceptions {
			if e.Type != nil && pairCovered[key] {
				t.Errorf("redundant exception %s: a pair already covers it", key)
			}
			if e.Type == nil {
				if !hit[key] {
					t.Errorf("exception %s matches nothing", key)
				}
				continue
			}
			want, found := structs[key]
			got := append([]string(nil), e.Fields...)
			sort.Strings(got)
			sort.Strings(want)
			if !found || !reflect.DeepEqual(got, want) || e.Type.Name() != key {
				t.Errorf("stale exception %s", key)
			}
		}
	})
}

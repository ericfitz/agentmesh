package server

import (
	"fmt"
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
}

// exception names a member a converter pair may not carry, with the reason.
// Keys are "gen:<Pair>.<path>" or "bus:<Pair>.<path>" (the side whose trip
// shows the diff), or a type name.
type exception struct {
	Type   reflect.Type // nil for a member-level entry; set for a whole-type entry
	Fields []string
	Reason string
}

var exceptions = map[string]exception{}

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
	"SigningKey.State":          "active",
	"SigningKey.Provider":       "store",
	"SigningKey.Algorithm":      "EdDSA",
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
					if _, excepted := exceptions[side+":"+linePath(l)]; excepted {
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
}

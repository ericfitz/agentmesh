package mcpserver

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
)

// toolCalls maps every MCP tool to the Bus methods its handler reaches
// (issue #29). TestToolCoverage walks the handlers and fails on a difference
// in either direction. A tool that goes through withSession inherits Open
// through resumeLapsed.
var toolCalls = map[string][]string{
	"register": {"Open", "Identities"}, "close_session": {"Close"},
	"create_channel": {"CreateChannel"}, "list_channels": {"ListChannels"}, "delete_channel": {"DeleteChannel"},
	"rename_channel": {"RenameChannel"}, "get_acl": {"ACL"}, "set_acl": {"SetACL"},
	"subscribe": {"Subscribe", "SubscribeTags"}, "unsubscribe": {"Unsubscribe", "UnsubscribeTags"},
	"send": {"Send", "Open"}, "receive": {"Receive", "Watch", "Open"}, "history": {"History"}, "search": {"Search"},
	"get_memory": {"GetMemory"}, "edit_memory": {"Edit"}, "delete_memory": {"Delete"},
	"discover": {"Identities"}, "set_status": {"SetAgentStatus", "Open"}, "health": {"Health"},
	"task_create": {"Create"}, "task_claim": {"Claim"}, "task_release": {"Release"},
	"task_update": {"Update"}, "task_get": {"GetTask"}, "task_list": {"List"},
}

// busMembers lists, for every bus struct type reachable from the inputs and
// results of the Bus methods the tools call, each exported member and whether
// a tool input or output carries it ("used") or not ("hidden: <reason>").
var busMembers = map[string]map[string]string{
	"ACLEntry": {
		"Identity":    "used",
		"Permissions": "used",
	},
	"AgentStatus": {
		"DisplayName": "used",
		"Identity":    "hidden: no documented reason (issue #29)",
		"LastTag":     "hidden: statusOut has no last_tag; LastTag is set on AgentStatuses entries only and is empty elsewhere (AgentStatus comment), and no tool reads AgentStatuses",
		"Problem":     "used",
		"Revision":    "used",
		"Session":     "hidden: no documented reason (issue #29)",
		"SetAt":       "used",
		"Tag":         "used",
		"Text":        "used",
	},
	"Channel": {
		"Capabilities": "used",
		"Kind":         "used",
		"Name":         "used",
	},
	"ChannelInfo": {
		"Channel":   "used",
		"CreatedAt": "used",
		"Creator":   "used",
		"Scope":     "hidden: create_channel's channelInfoOut has no scope; the create_channel description says a scoped agent names its channels <scope>-<name>",
	},
	"CloseSessionInput": {
		"IdempotencyKey": "hidden: no documented reason (issue #29)",
		"Session":        "used",
	},
	"CreateChannelInput": {
		"ACL":            "used",
		"IdempotencyKey": "used",
		"Kind":           "used",
		"Name":           "used",
		"Scope":          "hidden: no documented reason (issue #29)",
	},
	"DeleteChannelInput": {
		"IdempotencyKey": "used",
		"Name":           "used",
	},
	"DeleteMemoryInput": {
		"ID":             "used",
		"IdempotencyKey": "used",
	},
	"EditMemoryInput": {
		"Content":        "used",
		"ID":             "used",
		"IdempotencyKey": "used",
		"IfRevision":     "used",
		"Metadata":       "used",
		"Subject":        "used",
		"Tags":           "used",
		"Type":           "used",
	},
	"EditResult": {
		"MemoryID": "used",
		"Replaced": "used",
		"Revision": "used",
		"Seq":      "used",
	},
	"Gap": {
		"Channel": "used",
		"From":    "used",
		"To":      "used",
	},
	"Health": {
		"Embeddings":      "used",
		"Maintenance":     "used",
		"Notices":         "used",
		"Now":             "used",
		"ProtocolVersion": "used",
		"StartedAt":       "used",
		"Status":          "used",
		"Storage":         "used",
		"Store":           "used",
		"Tier":            "used",
		"Version":         "used",
	},
	"HealthEmbeddings": {
		"Backlog":      "used",
		"LastError":    "used",
		"LastErrorAt":  "used",
		"Model":        "used",
		"Rejected":     "used",
		"RejectedLast": "used",
		"State":        "used",
	},
	"HealthJob": {
		"Changed": "used",
		"Error":   "used",
		"Name":    "used",
		"Skipped": "used",
	},
	"HealthMaintenance": {
		"IntervalSeconds": "used",
		"Jobs":            "used",
		"LastTickAt":      "used",
		"Lock":            "used",
		"LockError":       "used",
		"Owner":           "used",
	},
	"HealthStore": {
		"Engine":        "used",
		"SchemaVersion": "used",
	},
	"HistoryInput": {
		"After":   "used",
		"Before":  "used",
		"Channel": "used",
		"Count":   "used",
		"Tags":    "used",
		"Thread":  "used",
	},
	"IdentityInfo": {
		"Admin":    "used",
		"Kind":     "used",
		"Name":     "used",
		"Sessions": "used",
		"Status":   "used",
	},
	"Message": {
		"Channel":     "used",
		"Content":     "used",
		"CreatedAt":   "used",
		"Display":     "used",
		"MatchedTags": "used",
		"MemoryID":    "used",
		"Metadata":    "used",
		"ReplyTo":     "used",
		"Revision":    "used",
		"Sender":      "used",
		"SenderKind":  "used",
		"Seq":         "used",
		"Session":     "used",
		"Subject":     "used",
		"Tags":        "used",
		"Type":        "used",
	},
	"Notice": {
		"Kind":    "used",
		"Message": "used",
		"SetAt":   "used",
	},
	"OfferedCursor": {
		"Channel": "used",
		"Seq":     "used",
	},
	"OpenSessionInput": {
		"Cursors":     "used",
		"Hint":        "used",
		"ResumeToken": "used",
	},
	"PendingChannel": {
		"Channel": "used",
		"Pending": "used",
	},
	"ReceiveInput": {
		"Ack":        "used",
		"Channels":   "used",
		"Count":      "used",
		"IncludeOwn": "used",
		"Session":    "used",
	},
	"ReceiveResult": {
		"AckIgnored":  "used",
		"Batch":       "used",
		"Gaps":        "used",
		"Instruction": "used",
		"Messages":    "used",
		"Notice":      "used",
		"Redelivered": "used",
	},
	"RejectedCursor": {
		"Channel": "used",
		"Reason":  "used",
	},
	"RenameChannelInput": {
		"IdempotencyKey": "used",
		"Name":           "used",
		"NewName":        "used",
	},
	"SearchHit": {
		"Message": "used",
		"Score":   "used",
	},
	"SearchInput": {
		"Channel": "used",
		"Count":   "used",
		"Cursor":  "used",
		"Mode":    "used",
		"Query":   "used",
		"Sender":  "used",
		"Since":   "used",
		"Tags":    "used",
		"Thread":  "used",
		"Until":   "used",
	},
	"SearchResult": {
		"Hits":                "used",
		"Next":                "used",
		"SemanticUnavailable": "used",
	},
	"SendInput": {
		"Channel":        "used",
		"Content":        "used",
		"IdempotencyKey": "used",
		"Metadata":       "used",
		"ReplyTo":        "used",
		"Session":        "used",
		"Subject":        "used",
		"Tags":           "used",
		"Type":           "used",
	},
	"SendResult": {
		"MemoryID": "used",
		"Seq":      "used",
	},
	"Session": {
		"DisplayName":     "used",
		"ID":              "used",
		"Identity":        "used",
		"Pending":         "used",
		"RejectedCursors": "used",
		"ResumeToken":     "used",
		"Resumed":         "used",
	},
	"SessionInfo": {
		"DisplayName": "used",
		"ID":          "used",
		"Identity":    "hidden: no documented reason (issue #29)",
		"OpenedAt":    "used",
	},
	"SetACLInput": {
		"Channel":        "used",
		"Entries":        "used",
		"IdempotencyKey": "used",
	},
	"SetAgentStatusInput": {
		"IdempotencyKey": "used",
		"Problem":        "used",
		"Session":        "used",
		"Tag":            "used",
		"Text":           "used",
	},
	"SubscribeInput": {
		"Channel":        "used",
		"From":           "used",
		"IdempotencyKey": "used",
	},
	"TagSubscribeInput": {
		"IdempotencyKey": "used",
		"Patterns":       "used",
	},
	"Task": {
		"Blocked":       "used",
		"BlockedBy":     "used",
		"Channel":       "used",
		"Description":   "used",
		"ID":            "used",
		"LeasedUntil":   "used",
		"Metadata":      "used",
		"OpenBlockers":  "used",
		"Owner":         "used",
		"Parent":        "used",
		"Rank":          "used",
		"ReclaimedAt":   "used",
		"ReclaimedFrom": "used",
		"Revision":      "used",
		"Status":        "used",
		"Subject":       "used",
		"UpdatedAt":     "used",
		"UpdatedBy":     "used",
	},
	"TaskClaimInput": {
		"ID":             "used",
		"IdempotencyKey": "used",
		"LeasedUntil":    "used",
	},
	"TaskCreateInput": {
		"After":          "used",
		"Before":         "used",
		"BlockedBy":      "used",
		"Channel":        "used",
		"Description":    "used",
		"IdempotencyKey": "used",
		"Metadata":       "used",
		"Parent":         "used",
		"Subject":        "used",
	},
	"TaskListInput": {
		"Channel": "used",
		"Owner":   "used",
		"Status":  "used",
	},
	"TaskPatch": {
		"AddBlockedBy":    "used",
		"After":           "used",
		"Before":          "used",
		"Delete":          "used",
		"Description":     "used",
		"ID":              "used",
		"IdempotencyKey":  "used",
		"LeasedUntil":     "used",
		"Metadata":        "used",
		"Owner":           "used",
		"Parent":          "used",
		"RemoveBlockedBy": "used",
		"Status":          "used",
		"Subject":         "used",
	},
	"TaskReleaseInput": {
		"ID":             "used",
		"IdempotencyKey": "used",
	},
	"TaskSummary": {
		"Depth":         "used",
		"HasDetails":    "used",
		"ID":            "used",
		"LeasedUntil":   "used",
		"OpenBlockers":  "used",
		"Owner":         "used",
		"Parent":        "used",
		"ReclaimedAt":   "used",
		"ReclaimedFrom": "used",
		"Status":        "used",
		"Subject":       "used",
	},
	"TaskUpdateResult": {
		"Deleted":  "used",
		"Replaced": "used",
		"Task":     "used",
	},
	"UnsubscribeInput": {
		"Channel":        "used",
		"IdempotencyKey": "used",
	},
	"Usage": {
		"BudgetBytes": "used",
		"Bytes":       "used",
		"DiskBytes":   "used",
		"DiskRatio":   "used",
		"Evictable":   "used",
		"Notice":      "used",
		"Tier":        "used",
	},
	"WatchInput": {
		"After":      "used",
		"IncludeOwn": "used",
		"Session":    "used",
		"Timeout":    "used",
	},
	"WatchResult": {
		"Channels": "hidden: no documented reason (issue #29)",
		"Count":    "hidden: no documented reason (issue #29)",
		"Seq":      "used",
		"Woke":     "used",
	},
}

func parseMCPServer(t *testing.T) ([]*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	_, self, _, _ := runtime.Caller(0)
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(self), "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no non-test files parsed")
	}
	return files, fset
}

func funcIndex(t *testing.T, files []*ast.File, fset *token.FileSet) map[string]*ast.FuncDecl {
	t.Helper()
	idx := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if prev, dup := idx[fd.Name.Name]; dup {
				t.Fatalf("function name %q declared twice (%s and %s): the by-name walk would be ambiguous",
					fd.Name.Name, fset.Position(prev.Pos()), fset.Position(fd.Pos()))
			}
			idx[fd.Name.Name] = fd
		}
	}
	return idx
}

// toolHandlers returns each AddTool call's tool name and handler expression.
func toolHandlers(files []*ast.File) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok || len(ce.Args) != 3 {
				return true
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "AddTool" {
				return true
			}
			ue, ok := ce.Args[1].(*ast.UnaryExpr)
			if !ok {
				return true
			}
			cl, ok := ue.X.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, el := range cl.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Name" {
					if bl, ok := kv.Value.(*ast.BasicLit); ok {
						name, err := strconv.Unquote(bl.Value)
						if err == nil {
							out[name] = ce.Args[2]
						}
					}
				}
			}
			return true
		})
	}
	return out
}

func busMethodSet() map[string]reflect.Method {
	bt := reflect.TypeOf((*bus.Bus)(nil)).Elem()
	m := map[string]reflect.Method{}
	for i := 0; i < bt.NumMethod(); i++ {
		m[bt.Method(i).Name] = bt.Method(i)
	}
	return m
}

func isBusReceiver(x ast.Expr) bool {
	switch v := x.(type) {
	case *ast.Ident:
		return v.Name == "b"
	case *ast.SelectorExpr:
		return v.Sel.Name == "Bus"
	}
	return false
}

// walkBusCalls returns the Bus methods reached from root, following calls
// into this package's own functions by name.
func walkBusCalls(root ast.Node, idx map[string]*ast.FuncDecl, methods map[string]reflect.Method) []string {
	found := map[string]bool{}
	visited := map[string]bool{}
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			var recv ast.Expr
			switch f := ce.Fun.(type) {
			case *ast.Ident:
				name = f.Name
			case *ast.SelectorExpr:
				name, recv = f.Sel.Name, f.X
			default:
				return true
			}
			if _, isBus := methods[name]; isBus && recv != nil && isBusReceiver(recv) {
				found[name] = true
				return true
			}
			if fd, ok := idx[name]; ok && !visited[name] {
				visited[name] = true
				walk(fd)
			}
			return true
		})
	}
	walk(root)
	out := make([]string, 0, len(found))
	for m := range found {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func handlerRoot(h ast.Expr, idx map[string]*ast.FuncDecl) ast.Node {
	switch v := h.(type) {
	case *ast.FuncLit:
		return v
	case *ast.SelectorExpr:
		if fd, ok := idx[v.Sel.Name]; ok {
			return fd
		}
	case *ast.Ident:
		if fd, ok := idx[v.Name]; ok {
			return fd
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func diffSets(want, got []string) (missing, extra []string) {
	w, g := map[string]bool{}, map[string]bool{}
	for _, s := range want {
		w[s] = true
	}
	for _, s := range got {
		g[s] = true
	}
	for _, s := range want {
		if !g[s] {
			missing = append(missing, s)
		}
	}
	for _, s := range got {
		if !w[s] {
			extra = append(extra, s)
		}
	}
	return
}

// collectBusStructs adds every struct type of package bus reachable from t.
func collectBusStructs(t reflect.Type, seen map[string]reflect.Type) {
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		collectBusStructs(t.Elem(), seen)
	case reflect.Map:
		collectBusStructs(t.Key(), seen)
		collectBusStructs(t.Elem(), seen)
	case reflect.Struct:
		if t.PkgPath() != reflect.TypeOf(bus.Error{}).PkgPath() {
			return
		}
		if _, ok := seen[t.Name()]; ok {
			return
		}
		seen[t.Name()] = t
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).IsExported() {
				collectBusStructs(t.Field(i).Type, seen)
			}
		}
	}
}

func TestToolCoverage(t *testing.T) {
	files, fset := parseMCPServer(t)
	idx := funcIndex(t, files, fset)
	handlers := toolHandlers(files)
	methods := busMethodSet()

	t.Run("tools", func(t *testing.T) {
		missing, extra := diffSets(sortedKeys(toolCalls), sortedKeys(handlers))
		if len(missing) > 0 || len(extra) > 0 {
			t.Errorf("toolCalls has no entry for the tools %v; it names tools no AddTool registers: %v", extra, missing)
		}
	})

	t.Run("calls", func(t *testing.T) {
		for _, tool := range sortedKeys(handlers) {
			want, ok := toolCalls[tool]
			if !ok {
				continue
			}
			root := handlerRoot(handlers[tool], idx)
			if root == nil {
				t.Errorf("tool %s: handler is neither a function literal nor a function of this package", tool)
				continue
			}
			got := walkBusCalls(root, idx, methods)
			w := append([]string(nil), want...)
			sort.Strings(w)
			missing, extra := diffSets(w, got)
			if len(missing) > 0 || len(extra) > 0 {
				t.Errorf("tool %s: the handler no longer calls %v and now also calls %v; update toolCalls and review busMembers", tool, missing, extra)
			}
		}
	})

	t.Run("members", func(t *testing.T) {
		seen := map[string]reflect.Type{}
		used := map[string]bool{}
		for _, ms := range toolCalls {
			for _, m := range ms {
				used[m] = true
			}
		}
		for _, name := range sortedKeys(used) {
			m, ok := methods[name]
			if !ok {
				t.Errorf("toolCalls names %s, which is not a bus.Bus method", name)
				continue
			}
			ft := m.Type
			for i := 1; i < ft.NumIn(); i++ { // index 0 is the receiver of a method value of an interface type? see below
				collectBusStructs(ft.In(i), seen)
			}
			if ft.NumOut() > 0 && ft.Out(0).String() != "error" {
				collectBusStructs(ft.Out(0), seen)
			}
		}
		for _, name := range sortedKeys(seen) {
			entry, ok := busMembers[name]
			if !ok {
				t.Errorf("bus type %s is reachable from a tool's Bus call but busMembers has no entry (members: %v)", name, exportedFields(seen[name]))
				continue
			}
			fields := exportedFields(seen[name])
			missing, extra := diffSets(fields, sortedKeys(entry))
			if len(missing) > 0 || len(extra) > 0 {
				t.Errorf("bus type %s: members without an entry %v; entries for no member %v", name, missing, extra)
			}
			for _, f := range sortedKeys(entry) {
				v := entry[f]
				if v != "used" && !strings.HasPrefix(v, "hidden: ") {
					t.Errorf("%s.%s: value %q is neither \"used\" nor \"hidden: <reason>\"", name, f, v)
				}
			}
		}
		for _, name := range sortedKeys(busMembers) {
			if _, ok := seen[name]; !ok {
				t.Errorf("busMembers entry %s is stale: no tool's Bus call reaches that type", name)
			}
		}
	})

	t.Run("aliases", func(t *testing.T) {
		isBusSel := func(e ast.Expr) bool {
			if u, ok := e.(*ast.UnaryExpr); ok {
				e = u.X
			}
			s, ok := e.(*ast.SelectorExpr)
			return ok && s.Sel.Name == "Bus"
		}
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				var rhs []ast.Expr
				switch v := n.(type) {
				case *ast.AssignStmt:
					rhs = v.Rhs
				case *ast.ValueSpec:
					rhs = v.Values
				default:
					return true
				}
				for _, e := range rhs {
					if isBusSel(e) {
						t.Errorf("%s: alias the Bus and the walk goes blind: call through c.Bus or the b parameter", fset.Position(n.Pos()))
					}
				}
				return true
			})
		}
	})
}

func exportedFields(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).IsExported() {
			out = append(out, t.Field(i).Name)
		}
	}
	sort.Strings(out)
	return out
}

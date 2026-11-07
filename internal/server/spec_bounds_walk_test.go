package server

import (
	"fmt"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// leaf is one bounded-kind node of the request side of the document: a
// string that is not an enum, an integer, a number, an array or a map.
type leaf struct {
	key    string
	kind   string // string, integer, number, array, map
	schema *openapi3.Schema
	// desc is the descriptions of the node and every container above it up
	// to its root (and the parameter's own), joined.
	desc string
}

// lowerFirst undoes the generator's capitalization of operationId: the keys
// name the operation as api/openapi.yaml does.
func lowerFirst(s string) string { return strings.ToLower(s[:1]) + s[1:] }

func refName(ref string) string { return ref[strings.LastIndex(ref, "/")+1:] }

func isType(s *openapi3.Schema, t string) bool { return s.Type != nil && s.Type.Is(t) }

// walkRequests visits every request parameter and request body schema of the
// document and returns the bounded-kind leaves, the keys visited (a key is
// visited even when it is a container), and the enum nodes met.
func walkRequests(doc *openapi3.T) (leaves map[string]leaf, enums []string) {
	leaves = map[string]leaf{}
	seen := map[string]bool{}
	var walk func(key, desc string, sr *openapi3.SchemaRef)
	walk = func(key, desc string, sr *openapi3.SchemaRef) {
		if sr == nil || sr.Value == nil {
			return
		}
		if sr.Ref != "" {
			name := refName(sr.Ref)
			if seen[name] {
				return
			}
			seen[name] = true
			key, desc = "schemas/"+name, ""
		}
		s := sr.Value
		desc += " " + s.Description
		for _, grp := range [][]*openapi3.SchemaRef{s.AllOf, s.OneOf, s.AnyOf} {
			for _, m := range grp {
				walk(key, desc, m)
			}
		}
		if len(s.Enum) > 0 {
			enums = append(enums, key)
			return
		}
		kind := ""
		switch {
		case isType(s, "string"):
			kind = "string"
		case isType(s, "integer"):
			kind = "integer"
		case isType(s, "number"):
			kind = "number"
		case isType(s, "array"):
			kind = "array"
		case isType(s, "object") && (s.AdditionalProperties.Schema != nil ||
			(s.AdditionalProperties.Has != nil && *s.AdditionalProperties.Has && len(s.Properties) == 0)):
			kind = "map"
		}
		if kind != "" {
			leaves[key] = leaf{key: key, kind: kind, schema: s, desc: desc}
		}
		names := make([]string, 0, len(s.Properties))
		for n := range s.Properties {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			walk(key+"."+n, desc, s.Properties[n])
		}
		if s.Items != nil {
			walk(key+"[]", desc, s.Items)
		}
		if s.AdditionalProperties.Schema != nil {
			walk(key+".<key>", desc, s.AdditionalProperties.Schema)
		}
	}
	params := func(opID string, ps openapi3.Parameters) {
		for _, p := range ps {
			if p.Value == nil {
				continue
			}
			if p.Ref != "" {
				name := refName(p.Ref)
				if seen["parameters/"+name] {
					continue
				}
				seen["parameters/"+name] = true
				walk("parameters/"+name, p.Value.Description, p.Value.Schema)
				continue
			}
			walk(fmt.Sprintf("operations/%s/%s/%s", opID, p.Value.In, p.Value.Name), p.Value.Description, p.Value.Schema)
		}
	}
	paths := make([]string, 0)
	for p := range doc.Paths.Map() {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		item := doc.Paths.Map()[p]
		params("", item.Parameters) // path-level parameters are shared; refs only
		for _, op := range item.Operations() {
			id := lowerFirst(op.OperationID)
			params(id, op.Parameters)
			if op.RequestBody == nil || op.RequestBody.Value == nil {
				continue
			}
			for _, mt := range op.RequestBody.Value.Content {
				walk("operations/"+id+"/body", "", mt.Schema)
			}
		}
	}
	return leaves, enums
}

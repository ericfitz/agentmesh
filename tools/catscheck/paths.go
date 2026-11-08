package main

import (
	"bytes"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// ChangedPaths lists the API paths (template spelling, sorted) affected by the
// change from old to new. docOnly is true when the normalized documents are
// equal (a documentation-only change, or none). Both inputs must be mappings
// (a nil document is the empty mapping). Task 2 adds the $ref widening of
// component changes; here a component change affects no path.
func ChangedPaths(old, new *yaml.Node) (paths []string, docOnly bool, err error) {
	o, n := Normalize(old), Normalize(new)
	for _, d := range []*yaml.Node{o, n} {
		if d.Kind != yaml.MappingNode {
			return nil, false, fmt.Errorf("the document is not a mapping")
		}
	}
	if bytes.Equal(canonical(o), canonical(n)) {
		return nil, true, nil
	}
	op, np := section(o, "paths"), section(n, "paths")
	set := map[string]bool{}
	// A top-level difference with no path of its own (openapi, servers,
	// security, webhooks, anything unknown) affects every request. info and
	// tags are documentation; paths and components are handled separately.
	for _, k := range unionNames(o, n) {
		switch k {
		case "info", "tags", "paths", "components":
			continue
		}
		if !bytes.Equal(canonical(member(o, k)), canonical(member(n, k))) {
			all := pathNames(np)
			if len(all) == 0 {
				all = pathNames(op)
			}
			for _, p := range all {
				set[p] = true
			}
			break
		}
	}
	for _, p := range unionNames(op, np) {
		if !bytes.Equal(canonical(member(op, p)), canonical(member(np, p))) {
			set[p] = true
		}
	}
	for p := range set {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, false, nil
}

// member returns the value of a top-level key, or nil when absent (nil
// canonicalizes to the empty mapping, distinct from no key only by being
// equal to an empty one, which is acceptable here).
func member(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "<absent>"}
}

func section(m *yaml.Node, key string) *yaml.Node {
	s := member(m, key)
	if s.Kind != yaml.MappingNode {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	return s
}

func pathNames(m *yaml.Node) []string {
	var out []string
	for i := 0; i+1 < len(m.Content); i += 2 {
		out = append(out, m.Content[i].Value)
	}
	return out
}

func unionNames(a, b *yaml.Node) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []*yaml.Node{a, b} {
		for _, k := range pathNames(m) {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

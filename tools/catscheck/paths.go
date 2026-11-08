package main

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// widen turns on the $ref widening: a path is also changed when a component
// in the $ref closure of its path item differs between the documents.
var widen = true // block 40 flips this to false

// componentSections are the sections of components a $ref may name.
var componentSections = map[string]bool{
	"schemas": true, "responses": true, "parameters": true, "examples": true,
	"requestBodies": true, "headers": true, "securitySchemes": true,
	"links": true, "callbacks": true, "pathItems": true,
}

// ChangedPaths lists the API paths (template spelling, sorted) affected by the
// change from old to new. docOnly is true when the normalized documents are
// equal or differ only in info and tags. Both inputs must be mappings (a nil
// document is the empty mapping). A path whose item is unchanged is still
// changed when a component in its $ref closure differs (widen).
func ChangedPaths(old, new *yaml.Node) (paths []string, docOnly bool, err error) {
	o, n := Normalize(old), Normalize(new)
	for i, d := range []*yaml.Node{o, n} {
		if d.Kind != yaml.MappingNode {
			return nil, false, fmt.Errorf("the %s document is not a mapping", []string{"old", "new"}[i])
		}
	}
	if bytes.Equal(canonical(o), canonical(n)) {
		return nil, true, nil
	}
	op, np := section(o, "paths"), section(n, "paths")
	set := map[string]bool{}
	otherDiff := false
	// A top-level difference with no path of its own (openapi, servers,
	// security, webhooks, anything unknown) affects every request. info and
	// tags are documentation; paths and components are handled separately.
	for _, k := range unionNames(o, n) {
		switch k {
		case "info", "tags", "paths", "components":
			continue
		}
		if !bytes.Equal(canonical(member(o, k)), canonical(member(n, k))) {
			otherDiff = true
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
	// Security schemes are reached by name from security, not by $ref, so a
	// change to one affects every request.
	if !bytes.Equal(canonical(member(section(o, "components"), "securitySchemes")),
		canonical(member(section(n, "components"), "securitySchemes"))) {
		otherDiff = true
		all := pathNames(np)
		if len(all) == 0 {
			all = pathNames(op)
		}
		for _, p := range all {
			set[p] = true
		}
	}
	for _, p := range unionNames(op, np) {
		// Every $ref is validated, even under a path that changed directly.
		hit, err := refsChanged(o, n, member(op, p), member(np, p))
		if err != nil {
			return nil, false, fmt.Errorf("path %s: %w", p, err)
		}
		if !bytes.Equal(canonical(member(op, p)), canonical(member(np, p))) {
			set[p] = true
		}
		if widen {
			if hit {
				set[p] = true
			}
		}
	}
	for p := range set {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	// Only info and tags differ: documentation (ruling 3).
	docOnly = len(paths) == 0 && !otherDiff &&
		bytes.Equal(canonical(member(o, "components")), canonical(member(n, "components")))
	return paths, docOnly, nil
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

// refsChanged reports whether a component in the $ref closure of the old or
// the new path item differs between the documents (a component present in one
// document only counts as different). A $ref that is not
// #/components/<section>/<name> with a known section is an error.
func refsChanged(oldDoc, newDoc, oldItem, newItem *yaml.Node) (bool, error) {
	seen := map[string]bool{}
	for _, side := range []struct{ doc, item *yaml.Node }{{oldDoc, oldItem}, {newDoc, newItem}} {
		if err := closure(side.doc, side.item, seen); err != nil {
			return false, err
		}
	}
	for key := range seen {
		sec, name, _ := strings.Cut(key, "/")
		a := member(section(section(oldDoc, "components"), sec), name)
		b := member(section(section(newDoc, "components"), sec), name)
		if !bytes.Equal(canonical(a), canonical(b)) {
			return true, nil
		}
	}
	return false, nil
}

// closure adds "<section>/<name>" of every component reachable from node in
// doc to seen; it is cycle-safe because a component is walked once.
func closure(doc, node *yaml.Node, seen map[string]bool) error {
	refs, err := collectRefs(node, nil)
	if err != nil {
		return err
	}
	for _, key := range refs {
		if seen[key] {
			continue
		}
		seen[key] = true
		sec, name, _ := strings.Cut(key, "/")
		comp := member(section(section(doc, "components"), sec), name)
		if err := closure(doc, comp, seen); err != nil {
			return err
		}
	}
	return nil
}

// collectRefs returns the component keys of every $ref scalar under n.
func collectRefs(n *yaml.Node, out []string) ([]string, error) {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value == "$ref" && v.Kind == yaml.ScalarNode {
				key, err := parseRef(v.Value)
				if err != nil {
					return nil, err
				}
				out = append(out, key)
				continue
			}
			var err error
			if out, err = collectRefs(v, out); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	for _, ch := range n.Content {
		var err error
		if out, err = collectRefs(ch, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseRef accepts only #/components/<section>/<name> and returns
// "<section>/<name>" (JSON pointer escapes decoded).
func parseRef(ref string) (string, error) {
	rest, ok := strings.CutPrefix(ref, "#/components/")
	parts := strings.Split(rest, "/")
	if !ok || len(parts) != 2 || !componentSections[parts[0]] || parts[1] == "" {
		return "", fmt.Errorf("unsupported $ref %q (want #/components/<section>/<name>)", ref)
	}
	name := strings.NewReplacer("~1", "/", "~0", "~").Replace(parts[1])
	return parts[0] + "/" + name, nil
}

// Command catscheck supports the CATS fuzzing campaign (issue #30): it
// normalizes api/openapi.yaml so a documentation-only change is recognized, and
// lists the API paths a change affects. It imports the standard library and
// gopkg.in/yaml.v3 only and works on the YAML tree, not a parsed document.
package main

import (
	"bytes"
	"sort"

	"gopkg.in/yaml.v3"
)

// strippedKeys are the documentation keys the normalizer removes (Eric's
// decision 3 of issue #30).
var strippedKeys = []string{"description", "summary", "example", "examples", "externalDocs"}

// nameMapKeys are the keys whose mapping value is keyed by user-chosen names,
// not by OpenAPI keywords; a name such as a property called "description" is
// never stripped there (ruling 2).
var nameMapKeys = map[string]bool{
	"properties":        true, // schema members, by property name
	"patternProperties": true, // schema members, by regular expression
	"paths":             true, // path templates
	"responses":         true, // status codes (and components.responses names)
	"headers":           true, // header names
	"links":             true, // link names
	"callbacks":         true, // callback names
	"encoding":          true, // property names
	"variables":         true, // server variable names
	"mapping":           true, // discriminator values
	"securitySchemes":   true, // scheme names
	"requestBodies":     true, // components.requestBodies names
	"schemas":           true, // components.schemas names
	"parameters":        true, // components.parameters names (an operation's is a sequence)
}

func isStripped(key string) bool {
	for _, k := range strippedKeys {
		if k == key {
			return true
		}
	}
	return false
}

// Normalize returns a deep copy of doc with the documentation keys removed by
// position (see strip). doc may be a document node or its root.
func Normalize(doc *yaml.Node) *yaml.Node {
	root := root(doc)
	out := clone(root)
	strip(out, false)
	return out
}

// root unwraps a document node; nil or an empty document is the empty mapping.
func root(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		return n.Content[0]
	}
	if n == nil || n.Kind == 0 {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	return n
}

func clone(n *yaml.Node) *yaml.Node {
	c := *n
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, ch := range n.Content {
		c.Content[i] = clone(ch)
	}
	return &c
}

// strip deletes the stripped keys from a mapping that was not reached through
// a name-map key, then recurses; the values of a name map are reached with
// keysAreNames true.
func strip(n *yaml.Node, keysAreNames bool) {
	switch n.Kind {
	case yaml.MappingNode:
		if !keysAreNames {
			kept := n.Content[:0]
			for i := 0; i+1 < len(n.Content); i += 2 {
				if isStripped(n.Content[i].Value) {
					continue
				}
				kept = append(kept, n.Content[i], n.Content[i+1])
			}
			n.Content = kept
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			strip(n.Content[i+1], nameMapKeys[n.Content[i].Value])
		}
	case yaml.SequenceNode:
		for _, ch := range n.Content {
			strip(ch, false)
		}
	}
}

// canonical encodes n with mapping keys sorted recursively, block style and no
// comments, so equal content is byte-equal.
func canonical(n *yaml.Node) []byte {
	c := clone(root(n))
	sortKeys(c)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	// Encoding a yaml.Node cannot fail for a tree this package built.
	_ = enc.Encode(c)
	_ = enc.Close()
	return buf.Bytes()
}

func sortKeys(n *yaml.Node) {
	n.Style &^= yaml.FlowStyle
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	if n.Kind == yaml.MappingNode {
		type pair struct{ k, v *yaml.Node }
		pairs := make([]pair, 0, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			pairs = append(pairs, pair{n.Content[i], n.Content[i+1]})
		}
		sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].k.Value < pairs[j].k.Value })
		for i, p := range pairs {
			n.Content[2*i], n.Content[2*i+1] = p.k, p.v
		}
	}
	for _, ch := range n.Content {
		sortKeys(ch)
	}
}

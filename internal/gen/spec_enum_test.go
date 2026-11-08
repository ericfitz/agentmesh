package gen_test

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// yaml11Words are the plain scalars a YAML 1.1 loader reads as a boolean or null
// rather than a string (issue #30, CATS: `enum: [off, ok, failing]` was loaded as
// [false, "ok", "failing"]).
var yaml11Words = map[string]bool{
	"y": true, "n": true, "yes": true, "no": true, "on": true, "off": true,
	"true": true, "false": true, "null": true, "~": true,
}

// TestEnumMembersAreNotYAML11Booleans fails when an enum member of
// api/openapi.yaml is a plain (unquoted) YAML 1.1 boolean word: a 1.1 loader
// reads it as a boolean, so the member has to be quoted.
func TestEnumMembersAreNotYAML11Booleans(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	checked := 0
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				if k.Value == "enum" && v.Kind == yaml.SequenceNode {
					for _, m := range v.Content {
						checked++
						if m.Kind == yaml.ScalarNode && m.Style == 0 && yaml11Words[strings.ToLower(m.Value)] {
							t.Errorf("line %d: enum member %s is a YAML 1.1 boolean word; quote it", m.Line, m.Value)
						}
					}
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&root)
	if checked == 0 {
		t.Fatal("no enum members found: the guard checks nothing")
	}
}

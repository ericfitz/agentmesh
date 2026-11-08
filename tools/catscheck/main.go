package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const usage = `usage:
  catscheck normalize FILE
  catscheck changed-paths OLD NEW
  catscheck classify --rules FILE [--max-lines N] REPORT_DIR
`

// say writes a message; a failed write to stdout or stderr has no remedy.
func say(w io.Writer, s string) { _, _ = io.WriteString(w, s) }

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is the dispatcher; it returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, usage)
		return 2
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") && a != "--rules" && a != "--max-lines" {
			say(stderr, fmt.Sprintf("catscheck: unknown flag %q\n", a)+usage)
			return 2
		}
	}
	switch args[0] {
	case "normalize":
		if len(args) != 2 {
			say(stderr, usage)
			return 2
		}
		doc, err := load(args[1], false)
		if err != nil {
			say(stderr, fmt.Sprintf("catscheck: %s: %v\n", args[1], err))
			return 2
		}
		_, _ = stdout.Write(canonical(Normalize(doc)))
		return 0
	case "changed-paths":
		if len(args) != 3 {
			say(stderr, usage)
			return 2
		}
		var docs [2]*yaml.Node
		for i, f := range args[1:] {
			d, err := load(f, true)
			if err != nil {
				say(stderr, fmt.Sprintf("catscheck: %s: %v\n", f, err))
				return 2
			}
			docs[i] = d
		}
		paths, docOnly, err := ChangedPaths(docs[0], docs[1])
		if err != nil {
			say(stderr, fmt.Sprintf("catscheck: changed-paths: %v\n", err))
			return 2
		}
		if len(paths) > 0 {
			say(stdout, strings.Join(paths, "\n")+"\n")
			return 10
		}
		if !docOnly {
			say(stderr, "catscheck: no path is affected\n")
		}
		return 0
	case "classify":
		return classifyCmd(args[1:], stdout, stderr)
	default:
		say(stderr, usage)
		return 2
	}
}

// load parses a YAML file. A missing file (when missingOK) or an empty
// document is the empty mapping; a non-mapping root is an error.
func load(path string, missingOK bool) (*yaml.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if missingOK && errors.Is(err, fs.ErrNotExist) {
			return root(nil), nil
		}
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	r := root(&doc)
	if r.Kind != yaml.MappingNode {
		return nil, errors.New("the document is not a mapping")
	}
	return r, nil
}

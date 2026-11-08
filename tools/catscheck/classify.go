package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// classifyCmd is `classify --rules FILE [--max-lines N] REPORT_DIR`.
func classifyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("classify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rulesFile := fs.String("rules", "", "rules file")
	maxLines := fs.Int("max-lines", 40, "cap on printed findings")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || *rulesFile == "" || *maxLines < 0 {
		say(stderr, usage)
		return 2
	}
	rules, err := LoadRules(*rulesFile)
	if err != nil {
		say(stderr, fmt.Sprintf("catscheck: %v\n", err))
		return 2
	}
	recs, err := loadReport(fs.Arg(0), stderr)
	if err != nil {
		say(stderr, fmt.Sprintf("catscheck: %s: %v\n", fs.Arg(0), err))
		return 2
	}
	if len(recs) == 0 {
		say(stderr, fmt.Sprintf("catscheck: no CATS test records in %s\n", fs.Arg(0)))
		return 2
	}
	var errs, warns, suppressed, findings, printed, more int
	used := map[string]bool{}
	clean := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")
	for _, rec := range recs {
		switch rec.Result {
		case "error":
			errs++
		case "warn":
			warns++
		case "success":
			continue
		default:
			// An unknown result is never dropped: a CATS version that adds one
			// must be looked at (Definition of Done B).
			say(stderr, fmt.Sprintf("catscheck: unknown result %q on %s %s (%s); want success, warn or error\n", rec.Result, clean.Replace(rec.Method), clean.Replace(rec.Path), clean.Replace(rec.Fuzzer)))
			return 2
		}
		fp, id, violation := Classify(rules, rec)
		switch {
		case fp:
			suppressed++
			used[id] = true
		case violation != "":
			findings++
			say(stdout, fmt.Sprintf("catscheck: rule %s matched a %d response and was refused (a 5xx is never a false positive; a 500 is a must-fix bug under the no-500 rule, Eric 2026-11-08, ADR 0001)\n", violation, rec.ResponseCode))
		default:
			findings++
			if printed >= *maxLines {
				more++
				continue
			}
			printed++
			say(stdout, fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\n", rec.Result, clean.Replace(rec.Method), clean.Replace(rec.Path), rec.ResponseCode, clean.Replace(rec.Fuzzer), clean.Replace(rec.ResultReason)))
		}
	}
	if more > 0 {
		say(stdout, fmt.Sprintf("... and %d more\n", more))
	}
	say(stdout, fmt.Sprintf("catscheck: %d tests, %d error, %d warn, %d suppressed by %d rule(s), %d finding(s)\n",
		len(recs), errs, warns, suppressed, len(used), findings))
	if findings > 0 {
		return 1
	}
	return 0
}

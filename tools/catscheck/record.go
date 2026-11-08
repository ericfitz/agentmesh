package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Record is one CATS test result, flattened the way the cats plugin's
// parse.record_from_json flattens it, so a rules file means the same thing
// to both engines.
type Record struct {
	Result              string
	ResponseCode        int
	Fuzzer              string
	Path                string
	ContractPath        string
	Method              string
	URL                 string
	Scenario            string
	ResultReason        string
	ResultDetails       string
	ResponseBody        string
	ResponseContentType string
	RequestBody         string
	JSONBody            any
	RequestHeaders      map[string]string
}

// requiredFields are the members a Test*.json must carry to be usable.
var requiredFields = []string{"testId", "traceId", "scenario", "expectedResult", "result", "fuzzer", "path", "server", "request", "response"}

// secretHeaders are redacted to a digest, as the plugin does, so a rule can
// never depend on a credential's value.
var secretHeaders = map[string]bool{"authorization": true, "cookie": true, "proxy-authorization": true}

var schemeRE = regexp.MustCompile(`(?s)^(\S+)\s+(\S.*)$`)

func redact(v string) string {
	if v == "" {
		return v
	}
	if m := schemeRE.FindStringSubmatch(v); m != nil {
		h := sha256.Sum256([]byte(m[2]))
		return m[1] + " sha256:" + hex.EncodeToString(h[:])[:12]
	}
	h := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(h[:])[:12]
}

func str(m map[string]any, k string) string {
	if s, ok := m[k].(string); ok {
		return s
	}
	return ""
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// recordFrom builds a Record from a decoded Test*.json and the raw bytes of
// its response.jsonBody.
func recordFrom(data map[string]any, rawBody []byte) Record {
	req := obj(data["request"])
	resp := obj(data["response"])
	r := Record{
		Fuzzer:              str(data, "fuzzer"),
		Path:                str(data, "path"),
		ContractPath:        str(data, "contractPath"),
		Method:              str(req, "httpMethod"),
		URL:                 str(req, "url"),
		Scenario:            str(data, "scenario"),
		ResultReason:        str(data, "resultReason"),
		ResultDetails:       str(data, "resultDetails"),
		ResponseContentType: str(resp, "responseContentType"),
		RequestHeaders:      map[string]string{},
	}
	r.Result = strings.ToLower(str(data, "result"))
	switch c := resp["responseCode"].(type) {
	case float64:
		r.ResponseCode = int(c)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(c)); err == nil {
			r.ResponseCode = n
		}
	}
	switch p := req["payload"].(type) {
	case string:
		r.RequestBody = p
	case nil:
	default:
		b, _ := json.Marshal(p)
		r.RequestBody = string(b)
	}
	if t := bytes.TrimSpace(rawBody); len(t) > 0 && string(t) != "null" {
		dec := json.NewDecoder(bytes.NewReader(t))
		dec.UseNumber()
		_ = dec.Decode(&r.JSONBody)
		r.ResponseBody = pyJSON(t)
	}
	if hs, ok := req["headers"].([]any); ok {
		for _, h := range hs {
			m := obj(h)
			k, ok := m["key"].(string)
			if !ok || k == "" {
				continue
			}
			v := ""
			if m["value"] != nil {
				if s, ok := m["value"].(string); ok {
					v = s
				} else {
					v = fmt.Sprint(m["value"])
				}
			}
			if secretHeaders[strings.ToLower(k)] {
				v = redact(v)
			}
			r.RequestHeaders[strings.ToLower(k)] = v
		}
	}
	return r
}

// LoadReport reads every Test*.json of dir, in numeric order, warning on
// stderr about a file it has to skip.
func LoadReport(dir string) ([]Record, error) { return loadReport(dir, os.Stderr) }

var numRE = regexp.MustCompile(`\d+`)

func testNumber(name string) int {
	if m := numRE.FindString(name); m != "" {
		if n, err := strconv.Atoi(m); err == nil {
			return n
		}
	}
	return math.MaxInt
}

func loadReport(dir string, warn io.Writer) ([]Record, error) {
	files, err := filepath.Glob(filepath.Join(dir, "Test*.json"))
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		if err == nil {
			err = fmt.Errorf("%s is not a directory", dir)
		}
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		a, b := filepath.Base(files[i]), filepath.Base(files[j])
		if na, nb := testNumber(a), testNumber(b); na != nb {
			return na < nb
		}
		return a < b
	})
	var out []Record
	for _, f := range files {
		name := filepath.Base(f)
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var data map[string]json.RawMessage
		if err := json.Unmarshal(b, &data); err != nil {
			say(warn, fmt.Sprintf("catscheck: skipping %s: %v\n", name, err))
			continue
		}
		var missing []string
		for _, k := range requiredFields {
			if _, ok := data[k]; !ok {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			say(warn, fmt.Sprintf("catscheck: skipping %s: missing fields %v\n", name, missing))
			continue
		}
		var all map[string]any
		if err := json.Unmarshal(b, &all); err != nil {
			say(warn, fmt.Sprintf("catscheck: skipping %s: %v\n", name, err))
			continue
		}
		var rr struct {
			JSONBody json.RawMessage `json:"jsonBody"`
		}
		_ = json.Unmarshal(data["response"], &rr)
		body := []byte(rr.JSONBody)
		out = append(out, recordFrom(all, body))
	}
	return out, nil
}

// pyJSON re-serializes JSON the way Python's json.dumps does for a value
// decoded by json.loads: ", " and ": " separators, object order kept,
// non-ASCII escaped, floats in repr form.
func pyJSON(raw []byte) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var sb strings.Builder
	if err := pyValue(dec, &sb); err != nil {
		return ""
	}
	return sb.String()
}

func pyValue(dec *json.Decoder, sb *strings.Builder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := t.(type) {
	case json.Delim:
		if v == '{' {
			sb.WriteByte('{')
			for first := true; dec.More(); first = false {
				if !first {
					sb.WriteString(", ")
				}
				k, err := dec.Token()
				if err != nil {
					return err
				}
				pyString(k.(string), sb)
				sb.WriteString(": ")
				if err := pyValue(dec, sb); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			sb.WriteByte('}')
			return err
		}
		sb.WriteByte('[')
		for first := true; dec.More(); first = false {
			if !first {
				sb.WriteString(", ")
			}
			if err := pyValue(dec, sb); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		sb.WriteByte(']')
		return err
	case string:
		pyString(v, sb)
	case bool:
		if v {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case nil:
		sb.WriteString("null")
	case json.Number:
		s := v.String()
		if !strings.ContainsAny(s, ".eE") {
			if s == "-0" {
				s = "0"
			}
			sb.WriteString(s)
			return nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return err
		}
		sb.WriteString(pyFloat(f))
	}
	return nil
}

func pyString(s string, sb *strings.Builder) {
	sb.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			sb.WriteString(`\"`)
		case r == '\\':
			sb.WriteString(`\\`)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r == '\b':
			sb.WriteString(`\b`)
		case r == '\f':
			sb.WriteString(`\f`)
		case r < 0x20:
			fmt.Fprintf(sb, `\u%04x`, r)
		case r < 0x7f:
			sb.WriteRune(r)
		case r >= 0x10000:
			a, b := utf16.EncodeRune(r)
			fmt.Fprintf(sb, `\u%04x\u%04x`, a, b)
		default:
			fmt.Fprintf(sb, `\u%04x`, r)
		}
	}
	sb.WriteByte('"')
}

// pyFloat formats like Python's repr(float).
func pyFloat(f float64) string {
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mant, expS, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expS)
	neg := strings.HasPrefix(mant, "-")
	digits := strings.ReplaceAll(strings.TrimPrefix(mant, "-"), ".", "")
	var out string
	if exp >= -4 && exp < 16 {
		switch {
		case exp < 0:
			out = "0." + strings.Repeat("0", -exp-1) + digits
		case len(digits) <= exp+1:
			out = digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
		default:
			out = digits[:exp+1] + "." + digits[exp+1:]
		}
	} else {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		sign := "+"
		if exp < 0 {
			sign = "-"
			exp = -exp
		}
		out = fmt.Sprintf("%se%s%02d", m, sign, exp)
	}
	if neg {
		out = "-" + out
	}
	return out
}

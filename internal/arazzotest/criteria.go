package arazzotest

import (
	"encoding/json"
	"strconv"
	"strings"
)

// criterion is one successCriteria condition: "<lhs> == <literal>" or
// "<lhs> != <literal>".
type criterion struct {
	text string
	lhs  expr
	neg  bool
	lit  any
}

func parseCondition(where, text string) (criterion, error) {
	c := criterion{text: text}
	op, at := splitOperator(text)
	if at < 0 {
		return c, unsupported(where, featCondition)
	}
	c.neg = op == "!="
	lhs := strings.TrimSpace(text[:at])
	rhs := strings.TrimSpace(text[at+2:])
	e, err := parseExpr(where, lhs)
	if err != nil {
		return c, err
	}
	if e.kind != exprStatus && (e.kind != exprBody || !e.hasPtr) {
		return c, unsupported(where, featCondition)
	}
	c.lhs = e
	lit, ok := parseLiteral(rhs)
	if !ok {
		return c, unsupported(where, featCondition)
	}
	c.lit = lit
	return c, nil
}

// splitOperator finds the first "==" or "!=" outside a double-quoted string.
func splitOperator(s string) (string, int) {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && inQuote:
			i++
		case s[i] == '"':
			inQuote = !inQuote
		case !inQuote && i+1 < len(s) && (s[i:i+2] == "==" || s[i:i+2] == "!="):
			return s[i : i+2], i
		}
	}
	return "", -1
}

func parseLiteral(s string) (any, bool) {
	switch s {
	case "true":
		return true, true
	case "false":
		return false, true
	case "null":
		return nil, true
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		u, err := strconv.Unquote(s)
		return u, err == nil
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return float64(i), true
	}
	return nil, false
}

func (c criterion) eval(where string, ec *evalCtx) (bool, error) {
	v, err := c.lhs.resolve(where, ec)
	if err != nil {
		return false, err
	}
	return jsonEqual(v, c.lit) != c.neg, nil
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

// jsonEqual compares two JSON scalars; numbers compare as float64, and a
// value of another type, an object or an array is never equal.
func jsonEqual(a, b any) bool {
	if af, ok := toFloat(a); ok {
		bf, ok := toFloat(b)
		return ok && af == bf
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case nil:
		return b == nil
	}
	return false
}

package sessions

import (
	"regexp"
	"strings"
	"testing"
)

func TestResumeTokenPatternAgrees(t *testing.T) {
	re := regexp.MustCompile(ResumeTokenPattern)
	if ResumeTokenLen != 43 {
		t.Fatalf("ResumeTokenLen = %d", ResumeTokenLen)
	}
	for name, s := range map[string]string{
		"43 valid":      strings.Repeat("A", 43),
		"43 mixed":      strings.Repeat("a-_Z9", 8) + "abc",
		"42":            strings.Repeat("A", 42),
		"44":            strings.Repeat("A", 44),
		"plus":          strings.Repeat("A", 42) + "+",
		"newline":       strings.Repeat("A", 42) + "\n",
		"newline inner": strings.Repeat("A", 20) + "\n" + strings.Repeat("A", 22),
		"empty":         "",
	} {
		if got, want := validToken(s), re.MatchString(s); got != want {
			t.Errorf("%s: validToken %v, pattern %v", name, got, want)
		}
	}
}

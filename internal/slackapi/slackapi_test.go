package slackapi

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestValidTSAndName(t *testing.T) {
	ts := map[string]bool{
		"1700000000.000100":  true,
		"1700000000.000001":  true,
		"170000000.0001":     false,
		"x":                  false,
		"":                   false,
		"1700000000.0000011": false,
		"1700000000x000100":  false,
		"170000000a.000100":  false,
		"1700000000.00010a":  false,
		" 1700000000.000100": false,
	}
	for in, want := range ts {
		if got := ValidTS(in); got != want {
			t.Errorf("ValidTS(%q) = %v, want %v", in, got, want)
		}
	}
	names := map[string]bool{
		"job-1_a":               true,
		"a":                     true,
		strings.Repeat("a", 80): true,
		"Job":                   false,
		"a b":                   false,
		strings.Repeat("a", 81): false,
		"":                      false,
		"a.b":                   false,
		"é":                     false,
		"a\n":                   false,
	}
	for in, want := range names {
		if got := ValidChannelName(in); got != want {
			t.Errorf("ValidChannelName(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestErrorTexts(t *testing.T) {
	rl := &RateLimitedError{Method: "Post", RetryAfter: 3 * time.Second}
	if !strings.Contains(rl.Error(), "Post") || !strings.Contains(rl.Error(), "3s") {
		t.Errorf("rate limit text %q", rl.Error())
	}
	var target *RateLimitedError
	if !errors.As(error(rl), &target) || target.RetryAfter != 3*time.Second {
		t.Error("errors.As RateLimitedError")
	}
	ae := &APIError{Method: "Archive", Code: "restricted_action"}
	if !strings.Contains(ae.Error(), "Archive") || !strings.Contains(ae.Error(), "restricted_action") {
		t.Errorf("api error text %q", ae.Error())
	}
	for _, e := range []error{ErrNameTaken, ErrAlreadyArchived, ErrChannelGone, ErrChannelNotFound, ErrUserNotFound} {
		if e.Error() == "" {
			t.Error("empty sentinel text")
		}
	}
}

func TestChannelNamePatternAgrees(t *testing.T) {
	re := regexp.MustCompile(ChannelNamePattern)
	if MaxChannelNameLen != 80 {
		t.Fatalf("MaxChannelNameLen = %d", MaxChannelNameLen)
	}
	corpus := []string{
		"", "a", "job-1_a", "A", "a b", "a.b", "a/b", "日本", "a\n", "-", "_", "0",
		strings.Repeat("a", 80), strings.Repeat("a", 81), strings.Repeat("-", 80), strings.Repeat("z9", 40), strings.Repeat("z9", 41),
	}
	for _, name := range corpus {
		if got, want := re.MatchString(name), ValidChannelName(name); got != want {
			t.Errorf("%q: pattern %v, ValidChannelName %v", name, got, want)
		}
	}
}

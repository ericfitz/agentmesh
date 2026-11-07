package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
)

func wantMsg(t *testing.T, err error, msg string) {
	t.Helper()
	wantCode(t, err, bus.CodeValidation)
	if !strings.Contains(err.Error(), msg) {
		t.Fatalf("error %q lacks %q", err, msg)
	}
}

func TestCheckLabel(t *testing.T) {
	if err := CheckLabel("type", strings.Repeat("é", MaxLabelRunes)); err != nil {
		t.Fatalf("256 two-byte runes: %v", err)
	}
	wantMsg(t, CheckLabel("type", strings.Repeat("é", MaxLabelRunes+1)), "type must be at most 256 characters")
}

func TestCheckToken(t *testing.T) {
	if err := CheckToken("ack", strings.Repeat("x", MaxTokenBytes)); err != nil {
		t.Fatalf("1024 bytes: %v", err)
	}
	wantMsg(t, CheckToken("ack", strings.Repeat("x", MaxTokenBytes+1)), "ack must be at most 1024 bytes")
	wantMsg(t, CheckToken("ack", strings.Repeat("é", 513)), "ack must be at most 1024 bytes")
}

func TestCheckMetadata(t *testing.T) {
	mk := func(n int) map[string]string {
		m := map[string]string{}
		for i := range n {
			m[fmt.Sprintf("k%d", i)] = "v"
		}
		return m
	}
	if err := CheckMetadata(nil); err != nil {
		t.Fatalf("nil: %v", err)
	}
	if err := CheckMetadata(mk(32)); err != nil {
		t.Fatalf("32 keys: %v", err)
	}
	wantMsg(t, CheckMetadata(mk(33)), "metadata has 33 keys, at most 32")
	if err := CheckMetadata(map[string]string{strings.Repeat("é", 64): strings.Repeat("é", 1024)}); err != nil {
		t.Fatalf("64-rune key, 1024-rune value: %v", err)
	}
	wantMsg(t, CheckMetadata(map[string]string{strings.Repeat("é", 65): "v"}), "metadata key")
	wantMsg(t, CheckMetadata(map[string]string{strings.Repeat("é", 65): "v"}), "must be at most 64 characters")
	wantMsg(t, CheckMetadata(map[string]string{"k": strings.Repeat("é", 1025)}), "must be at most 1024 characters")
}

func TestCheckItems(t *testing.T) {
	if err := CheckItems("cursors", MaxArrayItems); err != nil {
		t.Fatal(err)
	}
	wantMsg(t, CheckItems("cursors", MaxArrayItems+1), "cursors has 257 entries, at most 256")
}

func TestNonNegative(t *testing.T) {
	for _, v := range []int64{0, 1, 1 << 62} {
		if err := NonNegative("after", v); err != nil {
			t.Fatalf("%d: %v", v, err)
		}
	}
	wantMsg(t, NonNegative("after", -1), "after must not be negative")
}

func TestAtLeastOne(t *testing.T) {
	if err := AtLeastOne("thread", 1); err != nil {
		t.Fatal(err)
	}
	wantMsg(t, AtLeastOne("thread", 0), "thread must be at least 1")
	wantMsg(t, AtLeastOne("thread", -3), "thread must be at least 1")
}

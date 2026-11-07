package bus

import (
	"slices"
	"testing"
)

func TestCodesSortedCopy(t *testing.T) {
	got := Codes()
	if len(got) != len(validCodes) || !slices.IsSorted(got) {
		t.Fatalf("Codes() = %v", got)
	}
	for _, c := range got {
		if !ValidCode(c) {
			t.Errorf("%s is not valid", c)
		}
	}
	got[0] = "x"
	if Codes()[0] == "x" {
		t.Error("Codes() shares storage")
	}
}

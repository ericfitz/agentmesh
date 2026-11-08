package server

import "testing"

// TestRespcheckExceptionsNotStale fails an entry of the no-500 exception table
// (Eric 2026-11-08) that names no operation of the real document or has no
// reason. The table is empty today.
func TestRespcheckExceptionsNotStale(t *testing.T) {
	for _, e := range specCheck(t).StaleExceptions(Spec()) {
		t.Errorf("stale or reasonless no-500 exception: %s %s (%q)", e.Method, e.Path, e.Reason)
	}
}

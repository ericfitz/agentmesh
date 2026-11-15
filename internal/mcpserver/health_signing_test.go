package mcpserver_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/mcpserver"
)

func healthDoc(t *testing.T, h bus.Health) map[string]any {
	t.Helper()
	b, err := json.Marshal(mcpserver.HealthJSON(h))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestHealthSigningOut: the health tool (and agentmesh health, which prints
// mcpserver.HealthJSON) carries every member of the signing section, the two
// certificates included, under the wire names; a nil section is absent.
func TestHealthSigningOut(t *testing.T) {
	cert := func(thumb string, base int64) *bus.HealthCertificate {
		return &bus.HealthCertificate{Thumbprint: thumb, NotBefore: base, NotAfter: base + 1, DaysLeft: 7}
	}
	h := bus.Health{Status: bus.HealthDegraded, Tier: bus.TierAdmin, Signing: &bus.HealthSigning{
		Installation: "acme-prod", Intermediate: cert("int", 10), Leaf: cert("leaf", 20),
		NextRenewalAt: 30, TrustNumber: 31, RootCRLNumber: 32, LeafCRLNumber: 33, LastFailureAt: 34,
		LastFailure: "renewal failed", Stopped: "root_expired",
	}}
	got := healthDoc(t, h)["signing"]
	want := map[string]any{
		"installation":    "acme-prod",
		"intermediate":    map[string]any{"thumbprint": "int", "not_before": 10.0, "not_after": 11.0, "days_left": 7.0},
		"leaf":            map[string]any{"thumbprint": "leaf", "not_before": 20.0, "not_after": 21.0, "days_left": 7.0},
		"next_renewal_at": 30.0, "trust_number": 31.0, "root_crl_number": 32.0, "leaf_crl_number": 33.0,
		"last_failure_at": 34.0, "last_failure": "renewal failed", "stopped": "root_expired",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("signing = %v, want %v", got, want)
	}
	h.Signing = nil
	if _, ok := healthDoc(t, h)["signing"]; ok {
		t.Error("a nil Signing is not omitted")
	}
	h.Signing = &bus.HealthSigning{Installation: "acme-prod"}
	s, _ := healthDoc(t, h)["signing"].(map[string]any)
	for _, k := range []string{"intermediate", "leaf", "last_failure", "stopped"} {
		if _, ok := s[k]; ok {
			t.Errorf("empty %s is not omitted", k)
		}
	}
}

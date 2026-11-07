package arazzotest_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/ericfitz/agentmesh/internal/arazzotest"
)

// repositoryWorkflows are the workflow ids of api/arazzo.yaml, one per
// journey of docs/journeys.md (J9 is two: the Slack message is injected
// between them), in document order. TestArazzoWorkflows (internal/e2e) runs
// them by these ids.
var repositoryWorkflows = []string{
	"register-and-login",
	"send-receive-ack",
	"memories",
	"task-claim-complete",
	"task-list-maintain",
	"admin-bootstrap",
	"search-history",
	"agent-status",
	"channel-access",
	"bridges",
	"bridges-inbound-remove",
	"signing-key-rotation",
}

// TestLoadRepositoryDocument loads the repository's Arazzo document: every
// step binds to an operationId of api/openapi.yaml and nothing in it is
// outside the runner's supported surface (an *UnsupportedError names the
// feature; the fix is the document's, never the runner's).
func TestLoadRepositoryDocument(t *testing.T) {
	doc, err := arazzotest.Load(filepath.Join("..", "..", "api", "arazzo.yaml"))
	if err != nil {
		t.Fatalf("Load(api/arazzo.yaml): %v", err)
	}
	if doc.Info.Title != "agentmesh" || doc.Info.Version != doc.OpenAPI.Info.Version {
		t.Errorf("info = %+v, want title agentmesh and the OpenAPI document's version %q", doc.Info, doc.OpenAPI.Info.Version)
	}
	var ids []string
	for _, wf := range doc.Workflows {
		ids = append(ids, wf.ID)
		if len(wf.Steps) == 0 {
			t.Errorf("workflow %s has no step", wf.ID)
		}
	}
	if !slices.Equal(ids, repositoryWorkflows) {
		t.Errorf("workflow ids = %q, want %q", ids, repositoryWorkflows)
	}
}

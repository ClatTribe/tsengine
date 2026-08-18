package cloudagent

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/estategraph"
)

// The cloud agent can SEE a cross-surface path via estate_context but cannot RECORD one — the
// grounding check is cloud-graph-only, by design. What matters is that the refusal says so. The
// generic message ("must start at the internet or a public resource") is worse than unhelpful
// here: it points the model at a cloud entry point that does not exist, which is an invitation to
// invent one. These tests pin the boundary AND its wording.
func TestRecordIssue_EstateNodeRefusalNamesTheRealBoundary(t *testing.T) {
	cc := twoSurfaceContext(t)

	out := tRecord(cc, map[string]any{
		"target": "arn:aws:s3:::acme-customer-pii",
		"path": []any{
			estategraph.Canonical("code", "AKIAIOSFODNN7EXAMPLE"),
			"arn:aws:iam::000000000000:role/deploy-role",
			"arn:aws:s3:::acme-customer-pii",
		},
		"severity": "high", "rationale": "leaked key reaches PII",
	})

	if !strings.HasPrefix(out, "REJECTED") {
		t.Fatalf("an estate-only path was accepted into the cloud agent's issues: %s", out)
	}
	if len(cc.Issues) != 0 {
		t.Fatalf("refused in text but recorded %d issue(s) anyway", len(cc.Issues))
	}
	if !strings.Contains(out, "estate node") {
		t.Errorf("refusal does not name the real boundary; the model is told to hunt for a cloud entry point that does not exist:\n%s", out)
	}
	if strings.Contains(out, "must start at the internet or a public resource") {
		t.Errorf("refusal still gives the misleading generic reason:\n%s", out)
	}
	t.Logf("boundary refusal: %s", out)
}

// The estate-aware message must not swallow ORDINARY grounding refusals — an invented cloud id is
// still an invented cloud id, and must be told so plainly.
func TestRecordIssue_InventedCloudNodeStillGetsTheGroundingRefusal(t *testing.T) {
	cc := twoSurfaceContext(t)

	out := tRecord(cc, map[string]any{
		"target": "arn:aws:s3:::acme-customer-pii",
		"path":   []any{"arn:aws:ec2:::instance/i-does-not-exist", "arn:aws:s3:::acme-customer-pii"},
	})
	if !strings.Contains(out, "not grounded") {
		t.Errorf("an invented cloud node should get the ordinary grounding refusal, got:\n%s", out)
	}
	if strings.Contains(out, "estate node") {
		t.Errorf("an invented cloud node was excused as a cross-surface pivot:\n%s", out)
	}
}

func twoSurfaceContext(t *testing.T) *Context {
	t.Helper()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	// The cloud account: deploy-role can read the PII bucket, and NOTHING in the account exposes
	// deploy-role. A cloud scanner is right to find no internet path here.
	snap := cloudgraph.Ingest(cloudgraph.Inventory{
		Provider: "aws", AccountID: "000000000000",
		Resources: []cloudgraph.InvResource{
			{ID: "arn:aws:iam::000000000000:role/deploy-role", Kind: "principal", Name: "deploy-role"},
			{ID: "arn:aws:s3:::acme-customer-pii", Kind: "data", Name: "acme-customer-pii", Sensitive: cloudgraph.SensHigh},
		},
		Grants: []cloudgraph.InvGrant{
			{Principal: "arn:aws:iam::000000000000:role/deploy-role", Resource: "arn:aws:s3:::acme-customer-pii"},
		},
	})

	// The estate adds the code surface: a committed key that authenticates as that role.
	g := estategraph.New()
	sec := estategraph.Canonical("code", "AKIAIOSFODNN7EXAMPLE")
	g.AddNode(estategraph.Node{ID: sec, Kind: estategraph.KindSecret, Name: "AKIA...", Surfaces: []string{"code"}})
	role := estategraph.Canonical("cloud", "arn:aws:iam::000000000000:role/deploy-role")
	g.AddNode(estategraph.Node{ID: role, Kind: estategraph.KindPrincipal, Name: "deploy-role", Surfaces: []string{"cloud"}})
	if err := g.AddEdge(estategraph.Edge{From: sec, To: role, Kind: estategraph.EdgeAssumes,
		Surface: "cloud", Evidence: []string{"f-leak"}, ObservedAt: now}); err != nil {
		t.Fatalf("fixture edge rejected: %v", err)
	}
	return &Context{Snap: snap, Estate: g}
}

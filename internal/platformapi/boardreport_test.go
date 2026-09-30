package platformapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func decodeBoard(t *testing.T, b []byte) boardReport {
	t.Helper()
	var r boardReport
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("decode: %v: %s", err, b)
	}
	return r
}

// Nothing scanned is UNMEASURED, and the headline must say so rather than report a clean zero.
func TestBoardReport_NothingScannedIsNotSafe(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1"})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	r := decodeBoard(t, do(h, "GET", "/v1/board-report", "t1", "").Body.Bytes())
	if !strings.Contains(r.Headline, "unmeasured, not safe") {
		t.Fatalf("an unscanned estate must not read as clean: %q", r.Headline)
	}
}

// The report's numbers are the product's numbers: exploited by the evidence rung, KEV from threat
// intel, accepted risks held back and counted separately, an unscanned asset named in the headline.
func TestBoardReport_CountsWhatIsProvenAndDisclosesWhatIsNot(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "web", TenantID: "t1", Type: "web_application", Target: "https://app.acme.com"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "old", TenantID: "t1", Type: "web_application", Target: "https://legacy.acme.com"})
	_ = st.PutEngagement(ctx, platform.Engagement{ID: "e1", TenantID: "t1", AssetID: "web", StartedAt: time.Now(), CompletedAt: time.Now()})
	exploited := types.Finding{ID: "f1", AssetID: "web", RuleID: "sqli", Endpoint: "https://app.acme.com/q", Severity: types.SeverityHigh,
		Tool: "web-investigate", VerificationStatus: types.VerificationVerified, Description: "[Exploitation PoC] predicate held"}
	kev := types.Finding{ID: "f2", AssetID: "web", RuleID: "grype::CVE-2021-44228", Endpoint: "https://app.acme.com/lib", Severity: types.SeverityCritical,
		ThreatIntel: &types.ThreatIntel{KEV: &types.KEVStatus{Listed: true, Ransomware: true}}}
	accepted := types.Finding{ID: "f3", AssetID: "web", RuleID: "hdr", Endpoint: "https://app.acme.com/", Severity: types.SeverityLow}
	for _, f := range []types.Finding{exploited, kev, accepted} {
		_ = st.PutFinding(ctx, "t1", f)
	}
	_ = st.PutIgnoreRule(ctx, platform.IgnoreRule{TenantID: "t1", IssueKey: crossdetect.DedupKey(accepted), Reason: "accepted_risk", At: time.Now()})
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	r := decodeBoard(t, do(h, "GET", "/v1/board-report", "t1", "").Body.Bytes())
	if r.Proven.OpenIssues != 2 || r.Proven.Exploited != 1 || r.Proven.KEV != 1 || r.Proven.Ransomware != 1 {
		t.Fatalf("proven counts wrong: %+v", r.Proven)
	}
	if r.Proven.HeldByDecision != 1 || r.Decisions.Undated != 1 {
		t.Fatalf("the accepted risk must be held back AND flagged as undated: %+v %+v", r.Proven, r.Decisions)
	}
	if r.Coverage.ScannedAssets != 1 || len(r.Coverage.NeverScanned) != 1 || r.Coverage.NeverScanned[0] != "https://legacy.acme.com" {
		t.Fatalf("the unscanned asset must be named: %+v", r.Coverage)
	}
	if !strings.Contains(r.Headline, "1 proven exploitable") || !strings.Contains(r.Headline, "never been scanned") {
		t.Fatalf("the headline must lead with proof and carry the coverage caveat: %q", r.Headline)
	}
	if r.Exposure.Objective.Gradeable {
		t.Fatal("no history and no objective cannot be graded")
	}
	if len(r.TopFixes) == 0 {
		t.Fatal("the top fixes must come from the fix plan")
	}
	md := do(h, "GET", "/v1/board-report?format=md", "t1", "").Body.String()
	for _, want := range []string{r.Headline, "What these numbers do not say", "Never scanned: https://legacy.acme.com"} {
		if !strings.Contains(md, want) {
			t.Fatalf("the downloadable report must carry %q:\n%s", want, md)
		}
	}
}

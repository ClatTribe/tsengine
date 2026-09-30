package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// storingSubmitter persists what reaches the desk, so the handler's own before/after count sees it.
type storingSubmitter struct {
	st  store.Store
	got []platform.Action
}

func (s *storingSubmitter) Submit(ctx context.Context, a platform.Action) (platform.Action, error) {
	a.Status = platform.ActPendingApproval
	s.got = append(s.got, a)
	return a, s.st.PutAction(ctx, a)
}

func lodash(id, asset, repo, cve string) types.Finding {
	return types.Finding{ID: id, AssetID: asset, RuleID: "grype::" + cve, Tool: "grype", Severity: types.SeverityHigh,
		Endpoint: repo + "/package-lock.json", Title: cve + " in lodash",
		ToolArgs: map[string]string{"pkg": "lodash", "installed_version": "4.17.0"}}
}

func planHarness(t *testing.T) (http.Handler, store.Store, *storingSubmitter) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "t1"})
	for _, a := range []platform.Asset{
		{ID: "api", TenantID: "t1", Type: "repository", Target: "acme/api", Owner: "priya@acme.com", Meta: map[string]string{"full_name": "acme/api"}},
		{ID: "web", TenantID: "t1", Type: "repository", Target: "acme/web", Meta: map[string]string{"full_name": "acme/web"}},
	} {
		_ = st.PutAsset(ctx, a)
	}
	for _, f := range []types.Finding{
		lodash("f1", "api", "acme/api", "CVE-2021-23337"),
		lodash("f2", "api", "acme/api", "CVE-2020-8203"),
		lodash("f3", "web", "acme/web", "CVE-2021-23337"),
		{ID: "f4", AssetID: "web", RuleID: "semgrep::sqli", Tool: "web-investigate", Severity: types.SeverityMedium,
			Endpoint: "acme/web/src/db.ts:12", Title: "SQL injection",
			VerificationStatus: types.VerificationVerified, Description: "[Exploitation PoC] predicate held"},
		{ID: "f5", AssetID: "web", RuleID: "coverage::nuclei-no-template", Endpoint: "acme/web", Severity: types.SeverityInfo},
	} {
		_ = st.PutFinding(ctx, "t1", f)
	}
	n := 0
	sub := &storingSubmitter{st: st}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", Submitter: sub,
		ProposeBatch: func(fs []types.Finding, a platform.Asset) []platform.Action {
			return remediate.ProposeBulk(fs, a, func() string { n++; return fmt.Sprintf("act%d", n) })
		}})
	return h, st, sub
}

func decodePlan(t *testing.T, b []byte) fixPlanResponse {
	t.Helper()
	var p fixPlanResponse
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("decode: %v: %s", err, b)
	}
	return p
}

func stepByKey(p fixPlanResponse, key string) *fixPlanStep {
	for i := range p.Steps {
		if p.Steps[i].Key == key {
			return &p.Steps[i]
		}
	}
	return nil
}

const lodashKey = "pkg:lodash@4.17.0"

// One vulnerable package in two repositories is ONE step — the work a team plans — spanning both, and
// the step that was PROVEN exploitable leads even though it is lower severity.
func TestFixPlan_OneStepPerChangeAcrossAssets_ProvenFirst(t *testing.T) {
	h, _, _ := planHarness(t)
	p := decodePlan(t, do(h, "GET", "/v1/fix-plan", "t1", "").Body.Bytes())
	if len(p.Steps) != 2 {
		t.Fatalf("want 2 steps (lodash upgrade + sqli), got %d: %+v", len(p.Steps), p.Steps)
	}
	if p.Steps[0].Key != "rule:semgrep::sqli" {
		t.Fatalf("the exploited finding must lead the plan, got %q first", p.Steps[0].Key)
	}
	s := stepByKey(p, lodashKey)
	if s == nil || s.Closes != 3 || len(s.Assets) != 2 {
		t.Fatalf("the lodash upgrade must be one step closing 3 findings across 2 repositories: %+v", s)
	}
	if s.Assets[0].ID != "api" || s.Assets[0].Owner != "priya@acme.com" || s.Assets[0].Findings != 2 {
		t.Fatalf("assets ranked by findings, owner carried: %+v", s.Assets)
	}
	if s.Assets[1].Owner != "" {
		t.Fatalf("an unowned repository must stay unowned, never defaulted: %+v", s.Assets[1])
	}
	if s.State.NotProposed != 3 {
		t.Fatalf("nothing proposed yet: %+v", s.State)
	}
}

// The plan is the issues list's plan: an in-force accepted risk is not step one, a lapsed one is back,
// and a coverage disclosure (an absence of testing) is never a step.
func TestFixPlan_HonoursRiskDecisionsAndDropsCoverageDisclosures(t *testing.T) {
	h, st, _ := planHarness(t)
	ctx := context.Background()
	sqli := findingNamed(t, st, "f4")
	_ = st.PutIgnoreRule(ctx, platform.IgnoreRule{TenantID: "t1", IssueKey: crossdetect.DedupKey(sqli), Reason: "accepted_risk",
		At: time.Now(), ExpiresAt: time.Now().AddDate(0, 0, 30)})
	p := decodePlan(t, do(h, "GET", "/v1/fix-plan", "t1", "").Body.Bytes())
	if stepByKey(p, "rule:semgrep::sqli") != nil || p.Ignored != 1 {
		t.Fatalf("an in-force accepted risk must not be on the plan and must be counted: %+v", p)
	}
	for _, s := range p.Steps {
		if s.Key == "rule:coverage::nuclei-no-template" {
			t.Fatal("a coverage disclosure asserts an absence of testing — there is nothing to fix")
		}
	}
	_ = st.PutIgnoreRule(ctx, platform.IgnoreRule{TenantID: "t1", IssueKey: crossdetect.DedupKey(sqli), Reason: "accepted_risk",
		At: time.Now().AddDate(0, 0, -100), ExpiresAt: time.Now().AddDate(0, 0, -1)})
	if p = decodePlan(t, do(h, "GET", "/v1/fix-plan", "t1", "").Body.Bytes()); stepByKey(p, "rule:semgrep::sqli") == nil {
		t.Fatal("a lapsed acceptance must put the step back on the plan")
	}
}

// Preparing a step proposes per REAL asset — one PR per repository, the two lodash CVEs in acme/api as
// ONE bulk PR — and preparing it again queues nothing.
func TestFixPlanPrepare_OnePRPerRepository_Idempotent(t *testing.T) {
	h, _, sub := planHarness(t)
	rec := do(h, "POST", "/v1/fix-plan/prepare", "t1", `{"key":"`+lodashKey+`"}`)
	if rec.Code != 200 {
		t.Fatalf("prepare: %d %s", rec.Code, rec.Body)
	}
	var out fixPlanPrepareResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Queued != 2 || out.Assets != 2 || out.Findings != 3 {
		t.Fatalf("want 2 actions (one per repository) covering 3 findings: %+v", out)
	}
	for _, a := range sub.got {
		if a.Kind != platform.ActOpenPR {
			t.Fatalf("a repository finding proposed against its real asset must be a PR, got %q", a.Kind)
		}
		if a.Payload["full_name"] == "acme/api" && len(a.FindingKeys) != 2 {
			t.Fatalf("the acme/api PR must carry BOTH findings' keys so retest can confirm it: %+v", a.FindingKeys)
		}
	}
	again := do(h, "POST", "/v1/fix-plan/prepare", "t1", `{"key":"`+lodashKey+`"}`)
	var out2 fixPlanPrepareResponse
	_ = json.Unmarshal(again.Body.Bytes(), &out2)
	if out2.Queued != 0 || out2.Pending == 0 {
		t.Fatalf("preparing twice must not queue the work twice: %+v", out2)
	}
	p := decodePlan(t, do(h, "GET", "/v1/fix-plan", "t1", "").Body.Bytes())
	if s := stepByKey(p, lodashKey); s == nil || s.State.AwaitingApproval != 3 || !s.FixReady {
		t.Fatalf("the step must now read awaiting approval for all 3 findings: %+v", s)
	}
}

// A delivered fix is not a fixed vulnerability: it stays on the plan, and when a re-scan still finds it
// the step says the fix did not hold — matched by the stable key even though the finding id changed.
func TestFixPlan_FixThatDidNotHoldIsSaidAsSuch(t *testing.T) {
	h, st, _ := planHarness(t)
	ctx := context.Background()
	f3 := findingNamed(t, st, "f3")
	_ = st.PutAction(ctx, platform.Action{ID: "old", TenantID: "t1", FindingID: "f3-last-week", Status: platform.ActApplied,
		FindingKeys:  []string{detect.Key(f3)},
		Verification: &platform.FixVerification{Status: platform.FixStatusStillPresent, StillPresent: []string{detect.Key(f3)}}})
	p := decodePlan(t, do(h, "GET", "/v1/fix-plan", "t1", "").Body.Bytes())
	if s := stepByKey(p, lodashKey); s == nil || s.State.FixDidNotHold != 1 || s.State.NotProposed != 2 {
		t.Fatalf("a fix a re-scan contradicted must read as not holding: %+v", s)
	}
}

func TestFixPlanPrepare_GoneStepIs404(t *testing.T) {
	h, _, _ := planHarness(t)
	if rec := do(h, "POST", "/v1/fix-plan/prepare", "t1", `{"key":"pkg:left-pad@0.0.1"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("a step with nothing open must 404, never report an empty success: %d", rec.Code)
	}
	if rec := do(h, "POST", "/v1/fix-plan/prepare", "t1", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("no key is a 400: %d", rec.Code)
	}
}

func findingNamed(t *testing.T, st store.Store, id string) types.Finding {
	t.Helper()
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no finding %s", id)
	return types.Finding{}
}

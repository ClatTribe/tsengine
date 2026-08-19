package platformapi

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/retest"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tenanteval"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// EVERY CASE SOURCE, DRIVEN THROUGH ITS REAL PRODUCER.
//
// The suppression source matched nothing for every tenant because it rebuilt an issue key by hand,
// and its unit test passed because the fixture encoded the same mistake. A fixture that reimplements
// the producer cannot catch a producer that changed. So this drives each source the way the product
// does — the reinstate endpoint, the ignore endpoint, retest.Verify — and asserts a case comes out.
//
// If one of these ever stops producing cases, a third of the customer's suite goes quiet and the
// page reads "no graded cases yet" rather than "something broke". That is the failure this test
// exists to make loud.
func TestEvalSources_EachOneProducesACaseThroughTheRealPath(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	h := NewHandler(d)
	ctx := t.Context()

	// --- source 1: a human REINSTATES a finding the filter dropped ---
	dropped := types.Finding{
		ID: "f-rein", RuleID: "nuclei::tech-detect", Endpoint: "https://acme.test/",
		Severity: types.SeverityLow, Title: "Technology fingerprint",
	}
	_ = st.PutEngagement(ctx, platform.Engagement{
		ID: "e1", TenantID: "t1", L15Dismissed: []types.Finding{dropped},
	})
	rec := do(h, "POST", "/v1/l15-audit/reinstate", "t1", `{"finding_id":"f-rein","by":"sec@acme.com"}`)
	if rec.Code != 200 {
		t.Fatalf("reinstate: %d %s", rec.Code, rec.Body.String())
	}

	// --- source 2: a human IGNORES an issue as a false positive ---
	noisy := types.Finding{
		ID: "f-noise", RuleID: "deviceposture::disk-unencrypted", Endpoint: "device:Test Laptop",
		Severity: types.SeverityHigh, Title: "Disk not encrypted",
	}
	_ = st.PutFinding(ctx, "t1", noisy)
	rec = do(h, "POST", "/v1/issues/ignore", "t1",
		`{"key":"`+crossdetect.DedupKey(noisy)+`","reason":"false_positive","by":"sec@acme.com"}`)
	if rec.Code != 200 {
		t.Fatalf("ignore: %d %s", rec.Code, rec.Body.String())
	}

	// --- source 3: a re-scan CONFIRMS a fix closed a finding ---
	realVuln := types.Finding{
		ID: "f-fixed", RuleID: "grype::CVE-2021-44228", Endpoint: "pkg:log4j",
		Severity: types.SeverityCritical, Title: "Log4Shell",
	}
	_ = st.PutFinding(ctx, "t1", realVuln)
	act := platform.Action{
		ID: "a1", TenantID: "t1", FindingID: "f-fixed", Status: platform.ActApplied,
		FindingKeys: []string{"grype::CVE-2021-44228|pkg:log4j"},
	}
	// The REAL verifier, against a scan in which the vuln is gone — which is what "fixed" means.
	verified := retest.Verify([]platform.Action{act}, []types.Finding{noisy}, time.Now().UTC())
	if len(verified) != 1 || verified[0].Verification == nil ||
		verified[0].Verification.Status != platform.FixStatusFixed {
		t.Fatalf("retest did not confirm the fix: %+v", verified)
	}
	_ = st.PutAction(ctx, verified[0])

	// --- now: all three must appear in the suite ---
	cases, err := d.evalCases(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[tenanteval.Source]bool{}
	for _, c := range cases {
		got[c.Source] = true
	}
	for _, want := range []tenanteval.Source{
		tenanteval.SourceReinstated, tenanteval.SourceIgnored, tenanteval.SourceConfirmedFix,
	} {
		if !got[want] {
			t.Errorf("[SILENT SOURCE] %q produced no case through the real path — a third of the "+
				"customer's suite would go quiet and the page would read as empty, not broken", want)
		}
	}
	t.Logf("all three sources produced cases: %d total", len(cases))
}

// The reinstate marker is written in one package and read in another. A constant means they cannot
// drift; this asserts the value the reader expects is the one the writer actually stamps.
func TestEvalSources_ReinstateStampsTheMarkerTheSuiteReads(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()
	_ = st.PutEngagement(ctx, platform.Engagement{ID: "e1", TenantID: "t1",
		L15Dismissed: []types.Finding{{ID: "f-x", RuleID: "r", Endpoint: "e"}}})

	if rec := do(h, "POST", "/v1/l15-audit/reinstate", "t1", `{"finding_id":"f-x","by":"a@b.c"}`); rec.Code != 200 {
		t.Fatalf("reinstate: %d %s", rec.Code, rec.Body.String())
	}
	all, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	for _, f := range all {
		if f.ID != "f-x" {
			continue
		}
		if f.DiscoveryMethod == nil || f.DiscoveryMethod.Primary != platform.DiscoveryHumanReinstated {
			t.Fatalf("reinstate stamped %v, but the suite reads %q",
				f.DiscoveryMethod, platform.DiscoveryHumanReinstated)
		}
		return
	}
	t.Fatalf("the reinstated finding is not in the store; sources: %d", len(all))
}

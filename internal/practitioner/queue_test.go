package practitioner

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func sampleData() []TenantData {
	return []TenantData{{
		TenantID:   "t1",
		TenantName: "Acme",
		Risks: []platform.Risk{
			{ID: "r1", Title: "Injection exposure", Proposed: true},     // pending
			{ID: "r2", Title: "Decided", Status: platform.RiskAccepted}, // not pending
		},
		Audits: []platform.AuditEngagement{{
			Framework:    "soc2",
			Attestations: []platform.ControlAttestation{{Verdict: platform.AttestPending}, {Verdict: platform.AttestPassed}},
		}},
		Pentests: []pentest.Engagement{
			{ID: "p1", Name: "Q3 pentest", Status: pentest.StatusComplete},                                     // unsigned → pending
			{ID: "p2", Name: "Signed", Status: pentest.StatusComplete, Signoff: &pentest.Signoff{Signer: "X"}}, // signed → not pending
		},
		Policies: []platform.Policy{
			{Name: "Access Control", Status: platform.PolicyDraft}, // pending
			{Name: "Published", Status: platform.PolicyPublished},  // not pending
		},
	}}
}

func TestQueue_AllKinds(t *testing.T) {
	items := Queue(sampleData())
	if len(items) != 4 {
		t.Fatalf("want 4 pending items (risk/audit/pentest/policy), got %d: %+v", len(items), items)
	}
	kinds := map[string]int{}
	for _, it := range items {
		kinds[it.Kind]++
		if it.TenantName != "Acme" {
			t.Errorf("item missing tenant attribution: %+v", it)
		}
	}
	for _, k := range []string{"risk", "audit", "pentest", "policy"} {
		if kinds[k] != 1 {
			t.Errorf("want exactly 1 %s item, got %d", k, kinds[k])
		}
	}
}

func withScope(scope []string) []TenantData {
	d := sampleData()
	d[0].Scope = scope
	return d
}

func TestQueue_ScopeFilter(t *testing.T) {
	// a pentest-only practitioner sees only the pentest sign-off
	only := Queue(withScope([]string{"pentest"}))
	if len(only) != 1 || only[0].Kind != "pentest" {
		t.Fatalf("pentest scope should yield only the pentest item, got %+v", only)
	}
	// "vciso" expands to risk + policy
	vciso := Queue(withScope([]string{"vciso"}))
	got := map[string]bool{}
	for _, it := range vciso {
		got[it.Kind] = true
	}
	if len(vciso) != 2 || !got["risk"] || !got["policy"] {
		t.Fatalf("vciso scope should yield risk + policy, got %+v", vciso)
	}
}

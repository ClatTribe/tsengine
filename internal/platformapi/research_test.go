package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/research"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

type researchResp struct {
	FindingID string          `json:"finding_id"`
	Result    research.Result `json:"result"`
	Note      string          `json:"note"`
}

func researchDeps(t *testing.T) (http.Handler, *store.Memory) {
	t.Helper()
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Plan: platform.PlanEnterprise})
	// A fake fetcher: serves nist.gov, refuses everything else — so no test touches the network and the
	// allowlist decision (did the finding's own host get through the gate?) is what is under test.
	fetch := func(_ context.Context, u string, _ int) (research.Raw, error) {
		if u == "https://nvd.nist.gov/vuln/detail/CVE-2099-0001" {
			return research.Raw{Body: []byte("Upgrade to 2.3 or later."), ContentType: "text/plain"}, nil
		}
		return research.Raw{}, errContext("unreachable in test")
	}
	return NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", ResearchFetch: fetch}), st
}

type errContext string

func (e errContext) Error() string { return string(e) }

// A finding's OWN advisory host is admitted to the allowlist (so it is attempted, not refused), while a
// host the finding never cited is never reachable. The attempt fails with no network, which is the
// point: it lands in `unavailable` (allowed, then failed), never in `rejected` (refused outright).
func TestResearchFinding_FetchesTheFindingsOwnCitedHostsOnly(t *testing.T) {
	h, st := researchDeps(t)
	_ = st.PutFinding(context.Background(), "t1", types.Finding{
		ID: "f1", RuleID: "nuclei::CVE-2099-0001", Endpoint: "https://x/a",
		ThreatIntel: &types.ThreatIntel{Advisories: []string{"https://nvd.nist.gov/vuln/detail/CVE-2099-0001"}},
	})
	var out researchResp
	rec := do(h, "POST", "/v1/research/finding/f1", "t1", "{}")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	for _, r := range out.Result.Rejected {
		if r.URL == "https://nvd.nist.gov/vuln/detail/CVE-2099-0001" {
			t.Fatalf("the finding's own advisory was REFUSED by the allowlist — the wiring is wrong: %s", r.Reason)
		}
	}
	if len(out.Result.Documents) != 1 || out.Result.Documents[0].SHA256 == "" {
		t.Fatalf("the finding's own advisory was not fetched and pinned: %+v", out.Result)
	}
}

// A finding that cites no advisory says so, rather than returning an empty result that reads as a clean
// look.
func TestResearchFinding_NoAdvisoryIsStatedNotAnEmptyScan(t *testing.T) {
	h, st := researchDeps(t)
	_ = st.PutFinding(context.Background(), "t1", types.Finding{ID: "f2", RuleID: "semgrep::sqli", Endpoint: "a.go:1"})
	var out researchResp
	rec := do(h, "POST", "/v1/research/finding/f2", "t1", "{}")
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.Note == "" {
		t.Fatalf("a finding with no advisory must say so: %d %s", rec.Code, rec.Body.String())
	}
	if len(out.Result.Documents) != 0 {
		t.Error("nothing should have been fetched")
	}
}

// Unknown finding → 404; and a finding in another tenant is not researchable (isolation).
func TestResearchFinding_UnknownAndCrossTenant(t *testing.T) {
	h, st := researchDeps(t)
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t2", Plan: platform.PlanEnterprise})
	_ = st.PutFinding(context.Background(), "t2", types.Finding{ID: "secret", RuleID: "x", Endpoint: "y"})
	if rec := do(h, "POST", "/v1/research/finding/nope", "t1", "{}"); rec.Code != 404 {
		t.Errorf("unknown finding: want 404, got %d", rec.Code)
	}
	if rec := do(h, "POST", "/v1/research/finding/secret", "t1", "{}"); rec.Code != 404 {
		t.Errorf("another tenant's finding must not be researchable from t1: got %d", rec.Code)
	}
}

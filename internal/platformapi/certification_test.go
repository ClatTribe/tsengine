package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func certSetup(t *testing.T, inc platform.Incident, findings ...types.Finding) http.Handler {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	inc.TenantID = "t1"
	_ = st.PutIncident(ctx, inc)
	for _, f := range findings {
		_ = st.PutFinding(ctx, "t1", f)
	}
	return NewHandler(Deps{Store: st, Token: "platform-tok"})
}

func triagedIncident() platform.Incident {
	return platform.Incident{
		ID: "inc-1", Key: "operate::stale-account|ada@acme.io", RuleID: "operate::stale-account",
		Title: "Stale account", Severity: "high", Status: platform.IncidentOpen, FindingID: "f-001",
		TriageVerdict: "suspicious", TriageRationale: "privileged binding survived suspension",
		TriageSkill: "operate-stale-account@9f2c1a4b7e01",
	}
}

func mappedFinding() types.Finding {
	return types.Finding{ID: "f-001", RuleID: "operate::stale-account", Severity: types.SeverityHigh,
		Compliance: &types.Compliance{SOC2: []string{"CC6.1"}, ISO27001: []string{"A.5.16"}}}
}

func TestCertification_InheritsControlsAndPinsProvenance(t *testing.T) {
	h := certSetup(t, triagedIncident(), mappedFinding())
	rec := do(h, http.MethodGet, "/v1/incidents/inc-1/certification", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		ControlCount  int      `json:"control_count"`
		Frameworks    []string `json:"frameworks"`
		Attested      bool     `json:"attested"`
		Note          string   `json:"note"`
		Certification struct {
			Verdict     string `json:"verdict"`
			SkillName   string `json:"skill_name"`
			SkillDigest string `json:"skill_digest"`
		} `json:"certification"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ControlCount != 2 || len(body.Frameworks) != 2 {
		t.Errorf("controls should be inherited from the finding: count=%d frameworks=%v", body.ControlCount, body.Frameworks)
	}
	// Provenance must survive the "name@digest" round-trip so an auditor can identify the skill.
	if body.Certification.SkillName != "operate-stale-account" || body.Certification.SkillDigest != "9f2c1a4b7e01" {
		t.Errorf("provenance lost: %+v", body.Certification)
	}
	// §18.4: the engine proposes; it must never present itself as signed.
	if body.Attested {
		t.Error("a machine-produced certification must never be attested")
	}
	if body.Note == "" {
		t.Error("the response must say plainly that this is unattested")
	}
}

// An untriaged incident has nothing to certify. That is an honest empty state — not an error, and
// crucially not an empty certification, which would imply an assessment that never happened.
func TestCertification_UntriagedIncidentHasNothingToCertify(t *testing.T) {
	inc := triagedIncident()
	inc.TriageVerdict, inc.TriageRationale, inc.TriageSkill = "", "", ""
	h := certSetup(t, inc, mappedFinding())

	rec := do(h, http.MethodGet, "/v1/incidents/inc-1/certification", "t1", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", rec.Code, rec.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["reason"] != "not_triaged" {
		t.Errorf("want a machine-readable reason, got %v", body)
	}
}

// §10: refuse to certify against evidence we cannot read, rather than emitting an assessment with
// nothing underneath it.
func TestCertification_RefusesWhenTheCitedFindingIsGone(t *testing.T) {
	h := certSetup(t, triagedIncident()) // no findings stored
	rec := do(h, http.MethodGet, "/v1/incidents/inc-1/certification", "t1", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 when the evidence is unavailable, got %d: %s", rec.Code, rec.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["reason"] != "evidence_unavailable" {
		t.Errorf("want evidence_unavailable, got %v", body)
	}
}

// A finding with no compliance mapping yields no controls, and the summary must say so instead of
// presenting an unmapped assessment as compliance evidence.
func TestCertification_UnmappedFindingSaysSo(t *testing.T) {
	f := mappedFinding()
	f.Compliance = nil
	h := certSetup(t, triagedIncident(), f)

	rec := do(h, http.MethodGet, "/v1/incidents/inc-1/certification", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		ControlCount int    `json:"control_count"`
		Summary      string `json:"summary"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.ControlCount != 0 {
		t.Errorf("an unmapped finding must yield no controls, got %d", body.ControlCount)
	}
	if !contains(body.Summary, "no control mapping") {
		t.Errorf("summary must be honest about the absent mapping: %q", body.Summary)
	}
}

func TestCertification_UnknownIncident(t *testing.T) {
	h := certSetup(t, triagedIncident(), mappedFinding())
	if rec := do(h, http.MethodGet, "/v1/incidents/nope/certification", "t1", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestSplitSkillRef(t *testing.T) {
	for _, c := range []struct{ in, name, digest string }{
		{"skill@abc123", "skill", "abc123"},
		{"my@skill@abc", "my@skill", "abc"}, // splits on the LAST @, so a name containing @ survives
		{"bare", "bare", ""},                // no digest is honest, not guessed
		{"", "", ""},
	} {
		n, d := splitSkillRef(c.in)
		if n != c.name || d != c.digest {
			t.Errorf("splitSkillRef(%q) = (%q,%q), want (%q,%q)", c.in, n, d, c.name, c.digest)
		}
	}
}

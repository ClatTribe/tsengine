package grc

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestQuestionnaire_HardenedTenantAllYes(t *testing.T) {
	st := store.NewMemory()
	fullyOnboarded(t, st, "t1") // assessed everywhere, and clean — that is what "hardened" means
	g := &GRC{Store: st}
	q, err := g.Questionnaire(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	// Every OBSERVED question reads Yes — assessed everywhere and clean is exactly what the
	// fixture sets up. The attested ones do NOT: connecting systems cannot answer a question no
	// scan can reach, and a hardened estate is not a statement about background checks.
	if len(q.Answers) == 0 || q.InProgress != 0 {
		t.Fatalf("hardened tenant should have no gaps: %d yes / %d in-progress of %d", q.Yes, q.InProgress, len(q.Answers))
	}
	if q.Observed == 0 || q.Attested == 0 {
		t.Fatalf("corpus should hold both kinds, got observed=%d attested=%d", q.Observed, q.Attested)
	}
	if q.Yes != q.Observed {
		t.Errorf("hardened tenant: %d Yes of %d observed questions — a fully assessed, clean estate should "+
			"answer every evidenced question", q.Yes, q.Observed)
	}
	if q.NeedsYou != q.Attested {
		t.Errorf("NeedsYou = %d of %d attested — onboarding must not silently answer what only a person can",
			q.NeedsYou, q.Attested)
	}
}

func TestQuestionnaire_GapFlipsMappedQuestion(t *testing.T) {
	st := store.NewMemory()
	g := &GRC{Store: st}
	ctx := context.Background()
	fullyOnboarded(t, st, "t1") // so an UNRELATED question can legitimately read Yes
	// a finding citing SOC2 CC6.1 → AC-1 maps it → flips to In Progress.
	f := types.Finding{ID: "f-77", Severity: types.SeverityHigh, Compliance: &types.Compliance{SOC2: []string{"CC6.1"}}}
	if err := g.Apply(ctx, "t1", f); err != nil {
		t.Fatal(err)
	}

	q, err := g.Questionnaire(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]QAnswer{}
	for _, a := range q.Answers {
		byID[a.ID] = a
	}

	ac1 := byID["AC-1"]
	if ac1.Answer != "In Progress" {
		t.Errorf("AC-1 (CC6.1) should be In Progress, got %s", ac1.Answer)
	}
	if len(ac1.EvidenceIDs) != 1 || ac1.EvidenceIDs[0] != "f-77" {
		t.Errorf("AC-1 evidence should cite f-77, got %v", ac1.EvidenceIDs)
	}
	if !containsStr(ac1.GapControls, "soc2:CC6.1") {
		t.Errorf("AC-1 gap controls should include soc2:CC6.1, got %v", ac1.GapControls)
	}
	if byID["EM-1"].Answer != "Yes" {
		t.Errorf("unrelated EM-1 should remain Yes, got %s", byID["EM-1"].Answer)
	}
	if q.InProgress < 1 {
		t.Error("InProgress count should be ≥1")
	}

	md := RenderQuestionnaireMarkdown(q)
	if !strings.Contains(md, "In Progress") || !strings.Contains(md, "Security Questionnaire") {
		t.Errorf("markdown malformed:\n%s", md)
	}
}

func TestQuestionnaire_TenantIsolation(t *testing.T) {
	g := &GRC{Store: store.NewMemory()}
	ctx := context.Background()
	f := types.Finding{ID: "f-1", Severity: types.SeverityHigh, Compliance: &types.Compliance{SOC2: []string{"CC6.1"}}}
	_ = g.Apply(ctx, "t1", f)
	q, _ := g.Questionnaire(ctx, "t2") // different tenant
	if q.InProgress != 0 {
		t.Errorf("ISOLATION: t2 must see no gaps, got %d in-progress", q.InProgress)
	}
}

func containsStr(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

// fullyOnboarded seeds a tenant with an evidence source for every question domain — an
// identity provider, a cloud account, code, containers, web/API and a domain. THIS is what
// a "hardened tenant" means: assessed everywhere and clean. An EMPTY store is not hardened,
// it is unexamined, and the questionnaire must not answer "Yes" for it (see
// questionnaire_grounding_test.go).
func fullyOnboarded(t *testing.T, st *store.Memory, tenantID string) {
	t.Helper()
	ctx := context.Background()
	if err := st.PutConnection(ctx, platform.Connection{ID: "c-idp", TenantID: tenantID, Kind: platform.ConnOkta, Status: platform.ConnActive}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutConnection(ctx, platform.Connection{ID: "c-slack", TenantID: tenantID, Kind: platform.ConnSlack, Status: platform.ConnActive}); err != nil {
		t.Fatal(err)
	}
	for i, typ := range []string{"cloud_account", "repository", "container_image", "web_application", "api", "domain", "ip_address"} {
		if err := st.PutAsset(ctx, platform.Asset{ID: fmt.Sprintf("a-%d", i), TenantID: tenantID, Type: typ, Target: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	// The snapshot-driven posture sources have no connection and no asset — a device fleet or a
	// vendor portfolio arrives as a posted inventory, and PostureAssessed is stamped only after a
	// real ingest. Without them "fully onboarded" would silently mean "onboarded except for the
	// three asset classes a pure scanner misses", and the endpoint and vendor questions would
	// read Not assessed for a customer who had actually sent the data.
	tn, err := st.GetTenant(ctx, tenantID)
	if err != nil {
		tn = platform.Tenant{ID: tenantID}
	}
	tn.PostureAssessed = map[string]time.Time{
		"deviceposture": time.Now().UTC(),
		"tprm":          time.Now().UTC(),
		"sspm":          time.Now().UTC(),
		"osint":         time.Now().UTC(),
		// Training is stamped by the monitoring pass and ONLY when a roster exists, so it belongs
		// with the other posture sources rather than with the connections: a hardened tenant is one
		// whose workforce we can see and who are current, not one that merely connected an IdP.
		"training": time.Now().UTC(),
	}
	if err := st.PutTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
}

// HR-2 was promoted from the attested tier to the observed one. The promotion is only safe if a
// roster that has done NO training cannot answer "Yes" — that is the false-compliant mode the tier
// split exists to prevent, and it is worth its own test because the failure would be silent and
// would land in a document a buyer's procurement team reads.
func TestQuestionnaire_TrainingQuestionCannotAnswerYesForAnUntrainedRoster(t *testing.T) {
	ctx := context.Background()

	find := func(q *Questionnaire) QAnswer {
		t.Helper()
		for _, a := range q.Answers {
			if a.ID == "HR-2" {
				return a
			}
		}
		t.Fatal("HR-2 is not in the corpus")
		return QAnswer{}
	}

	// 1. Nothing stamped: we cannot see who works here, so the answer is NOT ASSESSED — never Yes.
	st := store.NewMemory()
	fullyOnboarded(t, st, "t1")
	tn, _ := st.GetTenant(ctx, "t1")
	delete(tn.PostureAssessed, "training")
	if err := st.PutTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	q, err := (&GRC{Store: st}).Questionnaire(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if a := find(q); a.Answer != AnswerNotAssessed {
		t.Errorf("with no roster assessed HR-2 answered %q; want %q", a.Answer, AnswerNotAssessed)
	}

	// 2. Assessed, and somebody owes their training: IN PROGRESS. The finding cites CC1.4, which is
	//    the control the question maps to, so the gap answers it — this is the case that makes the
	//    promotion honest rather than a Yes waiting to happen.
	st2 := store.NewMemory()
	fullyOnboarded(t, st2, "t1")
	owed := types.Finding{
		ID: "f-train", RuleID: "training::incomplete", Endpoint: "ada@acme.io",
		Severity: types.SeverityMedium, Title: "Ada has not completed 5 security training modules",
		Compliance: &types.Compliance{SOC2: []string{"CC1.4"}, PCI: []string{"12.6.1"}},
	}
	if err := st2.PutFinding(ctx, "t1", owed); err != nil {
		t.Fatal(err)
	}
	g2 := &GRC{Store: st2}
	// Apply is what OPENS the gap — the same call the runner makes for every finding it stores.
	if err := g2.Apply(ctx, "t1", owed); err != nil {
		t.Fatal(err)
	}
	q2, err := g2.Questionnaire(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if a := find(q2); a.Answer != AnswerInProgress {
		t.Errorf("with an outstanding training finding HR-2 answered %q; want %q — a roster that has "+
			"done nothing must never read as trained", a.Answer, AnswerInProgress)
	}

	// 3. Assessed and current: Yes. The mirror matters as much — a promotion that could only ever say
	//    "in progress" would be a permanent false negative traded for the false positive.
	if a := find(q); a.Answer == AnswerYes {
		t.Fatal("guard 1 was supposed to be Not assessed")
	}
	st3 := store.NewMemory()
	fullyOnboarded(t, st3, "t1")
	q3, err := (&GRC{Store: st3}).Questionnaire(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if a := find(q3); a.Answer != AnswerYes {
		t.Errorf("with the roster assessed and clean HR-2 answered %q; want %q", a.Answer, AnswerYes)
	}
}

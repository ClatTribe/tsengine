package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/training"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

const trainTenant = "ten-1"

// trainDeps builds a tenant with one signed-in user, and returns the deps plus that user's session
// token. The session is the point: both write paths take the acting person FROM it, so a test that
// passed the email in the body would prove nothing about the endpoint that actually ships.
func trainDeps(t *testing.T) (Deps, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{ID: trainTenant}); err != nil {
		t.Fatal(err)
	}
	u := platform.User{ID: "u1", TenantID: trainTenant, Email: "Ada@acme.io", Name: "Ada", Role: platform.RoleOwner}
	if err := st.PutUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	tok := "sess-ada"
	if err := st.PutSession(ctx, platform.Session{Token: tok, UserID: u.ID, TenantID: trainTenant, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st}, tok
}

func trainReq(method, path, body, token string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func getTraining(t *testing.T, d Deps, token string) trainingResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handleTraining(rec, trainReq(http.MethodGet, "/v1/training", "", token), trainTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/training: %d %s", rec.Code, rec.Body.String())
	}
	var got trainingResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// The delivered tier asserts that WE showed the content to THAT person, and a session is the only
// evidence of that. A platform-token call has no person behind it, so attributing the completion to
// anybody would put a name against training nobody watched them read.
func TestDeliveredCompletionRefusesARequestWithNoSignedInPerson(t *testing.T) {
	d, _ := trainDeps(t)
	rec := httptest.NewRecorder()
	d.handleTrainingComplete(rec, trainReq(http.MethodPost, "/v1/training/complete", `{"module_id":"phishing"}`, ""), trainTenant)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 with no session, got %d %s", rec.Code, rec.Body.String())
	}
	comps, _ := d.Store.ListTrainingCompletions(context.Background(), trainTenant)
	if len(comps) != 0 {
		t.Fatalf("stored %d completions for nobody", len(comps))
	}
}

// The subject comes from the SESSION and is never taken from the body — otherwise anyone could
// record that a colleague had read something.
func TestDeliveredCompletionTakesTheSubjectFromTheSessionNotTheBody(t *testing.T) {
	d, tok := trainDeps(t)
	rec := httptest.NewRecorder()
	d.handleTrainingComplete(rec,
		trainReq(http.MethodPost, "/v1/training/complete", `{"module_id":"phishing","subject":"grace@acme.io"}`, tok),
		trainTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	comps, _ := d.Store.ListTrainingCompletions(context.Background(), trainTenant)
	if len(comps) != 1 {
		t.Fatalf("want 1 completion, got %d", len(comps))
	}
	c := comps[0]
	if c.Subject != "ada@acme.io" {
		t.Errorf("subject = %q; the body must not be able to name someone else", c.Subject)
	}
	if c.Tier != platform.TrainingDelivered || c.Provider != training.SelfProvider {
		t.Errorf("tier/provider = %s/%s; a delivered record names this product", c.Tier, c.Provider)
	}
	if c.CurriculumVersion == "" {
		t.Error("no curriculum version recorded — the completion is evidence about content that can change")
	}
	if c.TenantID != trainTenant {
		t.Errorf("tenant = %q", c.TenantID)
	}
}

// The external endpoint records a SECOND-HAND claim. It must not be usable to mint the stronger
// tier, whatever the caller asks for.
func TestExternalRecordAlwaysLandsAsAttestedAndNamesWhoEnteredIt(t *testing.T) {
	d, tok := trainDeps(t)
	rec := httptest.NewRecorder()
	d.handleTrainingRecord(rec,
		trainReq(http.MethodPost, "/v1/training/record",
			`{"subject":"grace@acme.io","module_id":"phishing","provider":"KnowBe4","tier":"delivered"}`, tok),
		trainTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	comps, _ := d.Store.ListTrainingCompletions(context.Background(), trainTenant)
	if len(comps) != 1 {
		t.Fatalf("want 1, got %d", len(comps))
	}
	c := comps[0]
	if c.Tier != platform.TrainingAttested {
		t.Errorf("tier = %q; this endpoint may only record a second-hand claim", c.Tier)
	}
	if c.RecordedBy != "ada@acme.io" {
		t.Errorf("recorded_by = %q; it comes from the session, not the body", c.RecordedBy)
	}
	if c.Provider != "KnowBe4" {
		t.Errorf("provider = %q", c.Provider)
	}
}

// An external record with no provider is unverifiable, and the package refuses it. The endpoint must
// surface that as a 400 rather than storing something nobody can check.
func TestExternalRecordWithoutAProviderIsRefused(t *testing.T) {
	d, tok := trainDeps(t)
	rec := httptest.NewRecorder()
	d.handleTrainingRecord(rec,
		trainReq(http.MethodPost, "/v1/training/record", `{"subject":"grace@acme.io","module_id":"phishing"}`, tok),
		trainTenant)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "provider") {
		t.Fatalf("want 400 naming the provider, got %d %s", rec.Code, rec.Body.String())
	}
}

// Currency is measured from the completion date. Recording an old course as if it happened today
// would silently restart a clock that has already run out — and a date in the future would sit
// "current" for a year on the strength of a typo.
func TestExternalRecordHonoursTheRealDateAndRefusesTheFuture(t *testing.T) {
	d, tok := trainDeps(t)
	old := time.Now().AddDate(0, 0, -400).Format("2006-01-02")
	rec := httptest.NewRecorder()
	d.handleTrainingRecord(rec,
		trainReq(http.MethodPost, "/v1/training/record",
			`{"subject":"ada@acme.io","module_id":"phishing","provider":"KnowBe4","on":"`+old+`"}`, tok),
		trainTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	var got trainingResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Expired == 0 {
		t.Errorf("a 400-day-old completion did not read as expired: %+v", got.Summary)
	}

	future := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	rec2 := httptest.NewRecorder()
	d.handleTrainingRecord(rec2,
		trainReq(http.MethodPost, "/v1/training/record",
			`{"subject":"ada@acme.io","module_id":"accounts","provider":"KnowBe4","on":"`+future+`"}`, tok),
		trainTenant)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("future completion accepted: %d %s", rec2.Code, rec2.Body.String())
	}
}

// The roster is the denominator. An HRIS roster and the handful of people who have logged in here
// are different claims about who works at a company, so both are assembled and each person carries
// where they came from — and a LEAVER is not assigned training nobody can chase.
func TestRosterCombinesHRISAndUsersAndExcludesLeavers(t *testing.T) {
	d, tok := trainDeps(t)
	ctx := context.Background()
	if err := d.Store.ReplaceEmployees(ctx, trainTenant, "merge", []platform.Employee{
		{TenantID: trainTenant, Source: "merge", ID: "e1", Name: "Grace", WorkEmail: "grace@acme.io", Status: platform.EmploymentActive},
		{TenantID: trainTenant, Source: "merge", ID: "e2", Name: "Gone", WorkEmail: "gone@acme.io", Status: platform.EmploymentTerminated},
	}); err != nil {
		t.Fatal(err)
	}

	got := getTraining(t, d, tok)
	seen := map[string]string{}
	for _, s := range got.Statuses {
		seen[s.Subject] = s.State
	}
	if _, ok := seen["grace@acme.io"]; !ok {
		t.Error("active HRIS employee is not on the roster")
	}
	if _, ok := seen["ada@acme.io"]; !ok {
		t.Error("this product's own user is not on the roster")
	}
	if _, ok := seen["gone@acme.io"]; ok {
		t.Error("a terminated employee was assigned training — nobody can chase it and it inflates the gap")
	}
	if len(got.Summary.RosterSources) != 2 {
		t.Errorf("roster sources = %v; an HRIS roster and a user list are different claims and both are named",
			got.Summary.RosterSources)
	}
	if got.Me != "ada@acme.io" {
		t.Errorf("Me = %q; the page leads with what the reader owes", got.Me)
	}
}

// Confirming the same module twice in one sitting is one record, not two — but the history across
// years is kept, because "trained every year since 2024" is the thing an auditor asks for.
func TestRepeatedConfirmationIsIdempotentButHistoryIsKept(t *testing.T) {
	d, tok := trainDeps(t)
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		d.handleTrainingComplete(rec, trainReq(http.MethodPost, "/v1/training/complete", `{"module_id":"phishing"}`, tok), trainTenant)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	comps, _ := d.Store.ListTrainingCompletions(context.Background(), trainTenant)
	if len(comps) != 1 {
		t.Fatalf("three clicks in one day made %d records", len(comps))
	}

	// Last year's completion is a different record and survives alongside today's.
	lastYear, err := training.NewCompletion("ada@acme.io", "phishing", training.TierDelivered, "", "", "",
		time.Now().AddDate(-1, 0, 0), training.Default())
	if err != nil {
		t.Fatal(err)
	}
	lastYear.TenantID = trainTenant
	if err := d.Store.PutTrainingCompletion(context.Background(), lastYear); err != nil {
		t.Fatal(err)
	}
	comps, _ = d.Store.ListTrainingCompletions(context.Background(), trainTenant)
	if len(comps) != 2 {
		t.Fatalf("history collapsed: %d records, want 2", len(comps))
	}
}

// A completion recorded against somebody the roster does not know counts towards nothing — the
// roster is the denominator. Silently dropping it would leave whoever entered it watching a summary
// that never moves, so the summary NAMES them.
func TestACompletionForSomebodyOffTheRosterIsNamedNotSilentlyDropped(t *testing.T) {
	d, tok := trainDeps(t)
	rec := httptest.NewRecorder()
	d.handleTrainingRecord(rec,
		trainReq(http.MethodPost, "/v1/training/record",
			`{"subject":"contractor@elsewhere.io","module_id":"phishing","provider":"KnowBe4"}`, tok),
		trainTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	got := getTraining(t, d, tok)
	if len(got.Summary.OffRoster) != 1 || got.Summary.OffRoster[0] != "contractor@elsewhere.io" {
		t.Fatalf("OffRoster = %v; a record nobody counts must be named", got.Summary.OffRoster)
	}
	if !strings.Contains(got.Summary.Detail, "not on the roster") {
		t.Errorf("detail does not mention the uncounted record: %q", got.Summary.Detail)
	}
	if got.Summary.CompleteAttested != 0 {
		t.Errorf("an off-roster record was counted as progress: %+v", got.Summary)
	}
}

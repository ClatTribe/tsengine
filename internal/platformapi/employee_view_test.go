package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/training"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The employee allowlist admits GET /v1/training and GET /v1/program because an employee needs their
// OWN rows from each. Those two endpoints were then returning the whole company — every colleague's
// training status, every draft policy, every acknowledgement — to the one seat the role exists to
// keep out of the estate. The gate was right and the handlers behind it were not; these pin the
// handlers, since the allowlist test cannot see inside a 200.

func employeeSession(t *testing.T, d Deps, email string) string {
	t.Helper()
	ctx := context.Background()
	u := platform.User{ID: "u-" + email, TenantID: trainTenant, Email: email, Name: "Casey", Role: platform.RoleEmployee}
	if err := d.Store.PutUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	tok := "sess-" + email
	if err := d.Store.PutSession(ctx, platform.Session{Token: tok, UserID: u.ID, TenantID: trainTenant, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestEmployeeSeatSeesOnlyItsOwnTraining(t *testing.T) {
	d, owner := trainDeps(t)
	emp := employeeSession(t, d, "casey@acme.io")
	ctx := context.Background()

	// Ada (the owner) read a module here; Sam was recorded as trained by a vendor but is on no roster.
	ada, err := training.NewCompletion("ada@acme.io", "phishing", training.TierDelivered, "", "ada@acme.io", "", time.Now(), training.Default())
	if err != nil {
		t.Fatal(err)
	}
	ada.TenantID = trainTenant
	if err := d.Store.PutTrainingCompletion(ctx, ada); err != nil {
		t.Fatal(err)
	}
	sam, err := training.NewCompletion("sam@elsewhere.io", "phishing", training.TierAttested, "KnowBe4", "ada@acme.io", "", time.Now(), training.Default())
	if err != nil {
		t.Fatal(err)
	}
	sam.TenantID = trainTenant
	if err := d.Store.PutTrainingCompletion(ctx, sam); err != nil {
		t.Fatal(err)
	}

	got := getTraining(t, d, emp)
	if got.Scope != trainingScopeSelf {
		t.Errorf("scope = %q, want %q — the page reads this to drop the administration controls", got.Scope, trainingScopeSelf)
	}
	if got.Me != "casey@acme.io" {
		t.Errorf("me = %q", got.Me)
	}
	for _, st := range got.Statuses {
		if st.Subject != "casey@acme.io" {
			t.Errorf("an employee received a colleague's training row: %s / %s", st.Subject, st.ModuleID)
		}
	}
	if len(got.Statuses) != len(got.Curriculum.Modules) {
		t.Errorf("the employee should owe every module: %d rows for %d modules", len(got.Statuses), len(got.Curriculum.Modules))
	}
	if got.Summary.People != 1 || got.Summary.NoRoster {
		t.Errorf("the employee's own summary should describe one person, not the company or nobody: %+v", got.Summary)
	}
	if len(got.Summary.OffRoster) != 0 {
		t.Errorf("an employee was told which colleagues have off-roster records: %v", got.Summary.OffRoster)
	}
	if got.Summary.CompleteDelivered != 0 || got.Summary.CompleteAttested != 0 {
		t.Errorf("colleagues' completions leaked into the employee's counts: %+v", got.Summary)
	}

	// The owner's view is unchanged: everyone, every record, the off-roster name included.
	all := getTraining(t, d, owner)
	if all.Scope != trainingScopeEveryone {
		t.Errorf("owner scope = %q", all.Scope)
	}
	subjects := map[string]bool{}
	for _, st := range all.Statuses {
		subjects[st.Subject] = true
	}
	if !subjects["ada@acme.io"] || !subjects["casey@acme.io"] {
		t.Errorf("the owner should see the whole roster, got %v", subjects)
	}
	if len(all.Summary.OffRoster) != 1 || all.Summary.OffRoster[0] != "sam@elsewhere.io" {
		t.Errorf("the owner's summary lost the off-roster record: %v", all.Summary.OffRoster)
	}
}

func TestEmployeeSeatSeesOnlyPublishedPoliciesAndItsOwnAck(t *testing.T) {
	d, owner := trainDeps(t)
	emp := employeeSession(t, d, "casey@acme.io")
	ctx := context.Background()

	pub := platform.Policy{ID: "p-pub", TenantID: trainTenant, Name: "Acceptable Use", Status: platform.PolicyPublished,
		Owner: "ada@acme.io", Acks: []platform.PolicyAck{{User: "ada@acme.io", AckedAt: time.Now()}, {User: "casey@acme.io", AckedAt: time.Now()}}}
	draft := platform.Policy{ID: "p-draft", TenantID: trainTenant, Name: "Incident Response", Status: platform.PolicyDraft}
	for _, p := range []platform.Policy{pub, draft} {
		if err := d.Store.PutPolicy(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	list := func(tok string) (out struct {
		Policies []platform.Policy `json:"policies"`
		Scope    string            `json:"scope"`
	}) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/program", strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer "+tok)
		d.handleListProgram(rec, req, trainTenant)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /v1/program: %d %s", rec.Code, rec.Body.String())
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	mine := list(emp)
	if mine.Scope != trainingScopeSelf {
		t.Errorf("scope = %q", mine.Scope)
	}
	if len(mine.Policies) != 1 || mine.Policies[0].ID != "p-pub" {
		t.Fatalf("an employee should see only the published policy, got %+v", mine.Policies)
	}
	if len(mine.Policies[0].Acks) != 1 || mine.Policies[0].Acks[0].User != "casey@acme.io" {
		t.Errorf("an employee received colleagues' acknowledgements: %+v", mine.Policies[0].Acks)
	}

	theirs := list(owner)
	if theirs.Scope != trainingScopeEveryone || len(theirs.Policies) != 2 {
		t.Errorf("the owner's register changed: scope %q, %d policies", theirs.Scope, len(theirs.Policies))
	}
	for _, p := range theirs.Policies {
		if p.ID == "p-pub" && len(p.Acks) != 2 {
			t.Errorf("the owner lost acknowledgements: %+v", p.Acks)
		}
	}
}

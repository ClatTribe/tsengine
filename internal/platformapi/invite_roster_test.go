package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The roster invite is a bulk act that creates accounts for people who did not ask, so every rule
// below is a refusal: who is NOT seated, and that the response names them rather than folding them
// into a count.

func rosterDeps(t *testing.T) (Deps, platform.Session) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	owner := platform.User{ID: "u-owner", TenantID: "t1", Email: "ada@acme.io", Name: "Ada", Role: platform.RoleOwner}
	if err := st.PutUser(ctx, owner); err != nil {
		t.Fatal(err)
	}
	n := 0
	d := Deps{Store: st, NewID: func() string { n++; return "u-new-" + itoa(n) }}
	return d, platform.Session{UserID: owner.ID, TenantID: "t1"}
}

func seedRoster(t *testing.T, d Deps) {
	t.Helper()
	emps := []platform.Employee{
		{ID: "h1", Name: "Alice Active", WorkEmail: "Alice@acme.io", Status: platform.EmploymentActive, Department: "Eng"},
		{ID: "h1-dup", Name: "Alice Active", WorkEmail: "alice@acme.io", Status: platform.EmploymentActive}, // one person, two records
		{ID: "h2", Name: "Ada", WorkEmail: "ada@acme.io", Status: platform.EmploymentActive},                // already the owner
		{ID: "h3", Name: "Bob NoMail", Status: platform.EmploymentActive},                                   // no work email
		{ID: "h4", Name: "Carl Left", WorkEmail: "carl@acme.io", Status: platform.EmploymentTerminated, EndDate: "2026-01-31"},
		{ID: "h5", Name: "Dana Soon", WorkEmail: "dana@acme.io", Status: platform.EmploymentPending, StartDate: "2026-10-01"},
	}
	if err := d.Store.ReplaceEmployees(context.Background(), "t1", "merge", emps); err != nil {
		t.Fatal(err)
	}
}

func rosterCall(t *testing.T, d Deps, s platform.Session, method string, h func(http.ResponseWriter, *http.Request, platform.Session)) (*httptest.ResponseRecorder, rosterInviteResult) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(method, "/v1/auth/invite-roster", strings.NewReader("")), s)
	var out rosterInviteResult
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v\n%s", err, rec.Body.String())
		}
	}
	return rec, out
}

func emails(seats []rosterSeat) []string {
	var out []string
	for _, s := range seats {
		out = append(out, s.Email+"|"+s.HRISID)
	}
	return out
}

func TestRosterInvite_SeatsOnlyActiveUnseatedPeopleAndNamesTheRest(t *testing.T) {
	d, s := rosterDeps(t)
	seedRoster(t, d)

	rec, plan := rosterCall(t, d, s, http.MethodGet, d.handleRosterInvitePreview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body.String())
	}
	if plan.Roster != 6 || plan.NoRoster {
		t.Errorf("plan over the whole roster: %+v", plan.rosterInvitePlan)
	}
	if got := emails(plan.ToInvite); len(got) != 1 || plan.ToInvite[0].Email != "alice@acme.io" {
		t.Errorf("to_invite = %v; want alice once (lower-cased, deduped across two HRIS records)", got)
	}
	if len(plan.AlreadySeated) != 1 || plan.AlreadySeated[0].Email != "ada@acme.io" || plan.AlreadySeated[0].Role != platform.RoleOwner {
		t.Errorf("the owner in the HRIS export must be reported as already seated with her role, got %+v", plan.AlreadySeated)
	}
	if len(plan.Skipped) != 3 {
		t.Fatalf("skipped = %+v; want Bob (no email), Carl (left), Dana (not started)", plan.Skipped)
	}
	byID := map[string]rosterSeat{}
	for _, sk := range plan.Skipped {
		byID[sk.HRISID] = sk
	}
	if sk := byID["h3"]; sk.Name != "Bob NoMail" || !strings.Contains(sk.Reason, "no work email") {
		t.Errorf("a person with no address must be NAMED, not dropped: %+v", sk)
	}
	if sk := byID["h4"]; !strings.Contains(sk.Reason, "terminated") {
		t.Errorf("a leaver's reason must say so: %+v", sk)
	}
	if sk := byID["h5"]; !strings.Contains(sk.Reason, "pending") || !strings.Contains(sk.Reason, "2026-10-01") {
		t.Errorf("a pending hire's reason must carry the start date: %+v", sk)
	}
	if plan.Mailer {
		t.Error("no mailer is configured; the plan must say the passwords will be shown")
	}
	// Preview seated nobody.
	if _, err := d.Store.GetUserByEmail(context.Background(), "alice@acme.io"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the preview created an account: %v", err)
	}

	rec, res := rosterCall(t, d, s, http.MethodPost, d.handleRosterInvite)
	if rec.Code != http.StatusOK {
		t.Fatalf("invite: %d %s", rec.Code, rec.Body.String())
	}
	if len(res.Invited) != 1 || res.Invited[0].Email != "alice@acme.io" || res.Invited[0].Emailed || len(res.Invited[0].TempPassword) < 8 {
		t.Fatalf("invited = %+v; want alice with a temp password returned (no SMTP)", res.Invited)
	}
	u, err := d.Store.GetUserByEmail(context.Background(), "alice@acme.io")
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != platform.RoleEmployee || !u.MustChangePassword || u.Name != "Alice Active" {
		t.Errorf("the bulk act must mint EMPLOYEE seats with forced rotation, got %+v", u)
	}
	if len(res.Skipped) != 3 || len(res.AlreadySeated) != 1 || len(res.Failed) != 0 {
		t.Errorf("the result must carry the same naming as the plan: skipped %d seated %d failed %d", len(res.Skipped), len(res.AlreadySeated), len(res.Failed))
	}
	if !strings.Contains(res.Note, "1 person") || !strings.Contains(res.Note, "shown once") {
		t.Errorf("note = %q", res.Note)
	}

	// Idempotent: a second run seats nobody and reports Alice as already seated — never re-invited,
	// which would reset her credential.
	rec, again := rosterCall(t, d, s, http.MethodPost, d.handleRosterInvite)
	if rec.Code != http.StatusOK {
		t.Fatalf("second run: %d %s", rec.Code, rec.Body.String())
	}
	if len(again.Invited) != 0 || len(again.AlreadySeated) != 2 {
		t.Errorf("second run invited %d, already seated %d; want 0 and 2", len(again.Invited), len(again.AlreadySeated))
	}
	for _, seat := range again.AlreadySeated {
		if seat.Email == "alice@acme.io" && seat.Role != platform.RoleEmployee {
			t.Errorf("alice's seat reported as %q", seat.Role)
		}
	}
	if u2, _ := d.Store.GetUserByEmail(context.Background(), "alice@acme.io"); u2.PasswordHash != u.PasswordHash {
		t.Error("the second run reset an existing seat's credential")
	}
}

func TestRosterInvite_RefusesAnEmptyRosterRatherThanReportingZeroInvited(t *testing.T) {
	d, s := rosterDeps(t)
	rec, plan := rosterCall(t, d, s, http.MethodGet, d.handleRosterInvitePreview)
	if rec.Code != http.StatusOK || !plan.NoRoster || !strings.Contains(plan.Detail, "Connect") {
		t.Errorf("preview over no roster: %d %+v", rec.Code, plan.rosterInvitePlan)
	}
	rec, _ = rosterCall(t, d, s, http.MethodPost, d.handleRosterInvite)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "no_roster") {
		t.Errorf("an empty roster must be refused (409 no_roster), not answered '0 invited': %d %s", rec.Code, rec.Body.String())
	}
}

func TestRosterInvite_IsAnOwnersAct(t *testing.T) {
	d, _ := rosterDeps(t)
	seedRoster(t, d)
	member := platform.User{ID: "u-m", TenantID: "t1", Email: "mel@acme.io", Role: platform.RoleMember}
	if err := d.Store.PutUser(context.Background(), member); err != nil {
		t.Fatal(err)
	}
	ms := platform.Session{UserID: member.ID, TenantID: "t1"}
	if rec, _ := rosterCall(t, d, ms, http.MethodGet, d.handleRosterInvitePreview); rec.Code != http.StatusForbidden {
		t.Errorf("a member previewed the roster invite: %d", rec.Code)
	}
	if rec, _ := rosterCall(t, d, ms, http.MethodPost, d.handleRosterInvite); rec.Code != http.StatusForbidden {
		t.Errorf("a member ran the roster invite: %d", rec.Code)
	}
	if _, err := d.Store.GetUserByEmail(context.Background(), "alice@acme.io"); !errors.Is(err, store.ErrNotFound) {
		t.Error("a refused run still created a seat")
	}
}

// fakeMailer records sends; a non-nil fail makes every send fail.
type fakeMailer struct {
	sent []string
	fail error
}

func (m *fakeMailer) Send(_ context.Context, to, _, _ string) error {
	if m.fail != nil {
		return m.fail
	}
	m.sent = append(m.sent, to)
	return nil
}
func (m *fakeMailer) Configured() bool { return true }

func TestRosterInvite_MailsTheCredentialAndNeverReturnsItUnlessDeliveryFailed(t *testing.T) {
	d, s := rosterDeps(t)
	seedRoster(t, d)
	m := &fakeMailer{}
	d.Mailer = m

	_, plan := rosterCall(t, d, s, http.MethodGet, d.handleRosterInvitePreview)
	if !plan.Mailer || !strings.Contains(plan.Detail, "emailed") {
		t.Errorf("the plan must say the credential will be mailed: %+v", plan.rosterInvitePlan)
	}
	rec, res := rosterCall(t, d, s, http.MethodPost, d.handleRosterInvite)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if len(res.Invited) != 1 || !res.Invited[0].Emailed || res.Invited[0].TempPassword != "" {
		t.Errorf("with SMTP the password must go to the invitee and NOT come back: %+v", res.Invited)
	}
	if len(m.sent) != 1 || m.sent[0] != "alice@acme.io" {
		t.Errorf("sent = %v", m.sent)
	}
	if strings.Contains(res.Note, "shown once") {
		t.Errorf("note claims passwords are shown when none were: %q", res.Note)
	}

	// Delivery failure: the account exists, so the credential comes back for manual relay rather
	// than the request failing and stranding the seat.
	d2, s2 := rosterDeps(t)
	seedRoster(t, d2)
	d2.Mailer = &fakeMailer{fail: errors.New("smtp down")}
	_, res2 := rosterCall(t, d2, s2, http.MethodPost, d2.handleRosterInvite)
	if len(res2.Invited) != 1 || res2.Invited[0].Emailed || res2.Invited[0].TempPassword == "" {
		t.Errorf("a failed send must return the credential for relay: %+v", res2.Invited)
	}
}

// The single invite uses the same provisioning helper, so a freshly invited account is the same
// object through both doors. A regression here is one door minting a seat the other would not.
func TestSingleInviteStillMintsTheSameSeatShape(t *testing.T) {
	d, s := rosterDeps(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/invite", strings.NewReader(`{"email":"Casey@acme.io","name":"Casey","role":"employee"}`))
	rec := httptest.NewRecorder()
	d.handleInvite(rec, req, s)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		TempPassword string        `json:"temp_password"`
		Emailed      bool          `json:"emailed"`
		User         platform.User `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Emailed || len(out.TempPassword) < 8 || out.User.Email != "casey@acme.io" || out.User.Role != platform.RoleEmployee || !out.User.MustChangePassword || out.User.PasswordHash != "" {
		t.Errorf("single invite shape changed: %+v temp=%q emailed=%v", out.User, out.TempPassword, out.Emailed)
	}
	rec2 := httptest.NewRecorder()
	d.handleInvite(rec2, httptest.NewRequest(http.MethodPost, "/v1/auth/invite", strings.NewReader(`{"email":"casey@acme.io"}`)), s)
	if rec2.Code != http.StatusConflict {
		t.Errorf("a second invite for the same address must be 409, got %d", rec2.Code)
	}
	_ = time.Now
}

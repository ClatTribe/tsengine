package hris

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

var fixedNow = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

func opts() CorrelateOptions { return CorrelateOptions{Now: func() time.Time { return fixedNow }} }

func rules(fs []types.Finding) string {
	var r []string
	for _, f := range fs {
		r = append(r, f.RuleID+"@"+f.Endpoint+":"+string(f.Severity))
	}
	return strings.Join(r, " ")
}

func TestLeaverWithActiveAccountIsTheFinding(t *testing.T) {
	emps := []platform.Employee{
		{ID: "e1", Name: "Alice Leaver", WorkEmail: "alice@acme.io", Status: platform.EmploymentTerminated, EndDate: "2026-06-15"},
		{ID: "e2", Name: "Bob Admin", WorkEmail: "Bob@Acme.io", Status: platform.EmploymentTerminated, EndDate: "2026-08-30"},
		{ID: "e3", Name: "Carol Current", WorkEmail: "carol@acme.io", Status: platform.EmploymentActive},
		{ID: "e4", Name: "Dan Done", WorkEmail: "dan@acme.io", Status: platform.EmploymentTerminated, EndDate: "2026-01-10"},
		{ID: "e5", Name: "Eve Gone", WorkEmail: "eve@acme.io", Status: platform.EmploymentTerminated},
	}
	ws := operate.Workspace{Provider: "okta", Users: []operate.User{
		{Email: "alice@acme.io", Suspended: false, LastLoginDays: 3},
		{Email: "bob@acme.io", Admin: true, Suspended: false},
		{Email: "carol@acme.io"},
		{Email: "dan@acme.io", Suspended: true}, // offboarded correctly
		// eve has no account at all — also correct
	}}
	fs, rep := Correlate(emps, ws, opts())
	if len(fs) != 2 {
		t.Fatalf("want alice + bob, got %s", rules(fs))
	}
	// Ordered by severity: the admin leaver first.
	if fs[0].Endpoint != "bob@acme.io" || fs[0].Severity != types.SeverityCritical || fs[0].RuleID != "hris::leaver-with-active-account" {
		t.Errorf("an admin leaver is critical and first: %+v", fs[0])
	}
	if !strings.Contains(fs[0].Description, "administrator role") || !strings.Contains(fs[0].Description, "okta") {
		t.Errorf("description must name the role and the provider: %s", fs[0].Description)
	}
	if fs[1].Endpoint != "alice@acme.io" || fs[1].Severity != types.SeverityHigh {
		t.Errorf("a non-admin leaver is high: %+v", fs[1])
	}
	if !strings.Contains(fs[1].Description, "2026-06-15") || !strings.Contains(fs[1].Description, "79 days ago") {
		t.Errorf("the finding must carry the recorded date and its age: %s", fs[1].Description)
	}
	if fs[1].Compliance == nil || len(fs[1].Compliance.SOC2) == 0 {
		t.Error("offboarding findings map to SOC 2 CC6.2/CC6.3")
	}
	if rep.Terminated != 4 || rep.LeaversWithAccess != 2 || rep.LeaversDeprovisioned != 2 || rep.Matched != 4 {
		t.Errorf("report must count the successes too: %+v", rep)
	}
	if rep.Unmatched != 0 || len(rep.ChecksNotRun) != 0 {
		t.Errorf("every account matched a record: %+v", rep)
	}
	// Mutation guard: the case-insensitive match is load-bearing — Bob's HR record is capitalised.
	if fs[0].Endpoint != "bob@acme.io" {
		t.Error("email matching must be case-insensitive")
	}
}

func TestAFutureEndDateIsNotALeaver(t *testing.T) {
	emps := []platform.Employee{{ID: "e1", WorkEmail: "fay@acme.io", Status: platform.EmploymentActive, EndDate: "2026-09-30"}}
	ws := operate.Workspace{Provider: "gworkspace", Users: []operate.User{{Email: "fay@acme.io", Admin: true}}}
	fs, rep := Correlate(emps, ws, opts())
	if len(fs) != 0 || rep.Terminated != 0 {
		t.Fatalf("a scheduled departure is not a leaver: %s %+v", rules(fs), rep)
	}
	// …but a status of terminated with a future date still refuses (the date wins: HR said "leaves on").
	emps[0].Status = platform.EmploymentTerminated
	if fs, _ := Correlate(emps, ws, opts()); len(fs) != 0 {
		t.Fatalf("terminated-with-future-end-date is still scheduled, not gone: %s", rules(fs))
	}
	// A past end date with an ACTIVE status is a leaver — the HRIS recorded the date.
	emps[0].Status, emps[0].EndDate = platform.EmploymentActive, "2026-08-01"
	if fs, _ := Correlate(emps, ws, opts()); len(fs) != 1 {
		t.Fatalf("a recorded past end date decides: %s", rules(fs))
	}
}

func TestPersonalEmailIsAnAssertedJoinNotAGuess(t *testing.T) {
	emps := []platform.Employee{{ID: "e1", Name: "Gus", WorkEmail: "gus@corp.example", PersonalEmails: []string{"gus.personal@gmail.example"}, Status: platform.EmploymentTerminated, EndDate: "2026-07-01"}}
	ws := operate.Workspace{Provider: "okta", Users: []operate.User{{Email: "gus.personal@gmail.example"}}}
	fs, _ := Correlate(emps, ws, opts())
	if len(fs) != 1 || fs[0].RuleID != "hris::leaver-with-active-account" {
		t.Fatalf("an address the HRIS asserts belongs to the person joins: %s", rules(fs))
	}
	// And NO join on a resembling address — different mailbox, same person by eye.
	ws.Users[0].Email = "gus@gmail.example"
	fs, rep := Correlate(emps, ws, opts())
	if len(fs) != 1 || fs[0].RuleID != "hris::account-without-hr-record" {
		t.Fatalf("resemblance is not identity — the account must land as unmatched, got %s", rules(fs))
	}
	if rep.Unmatched != 1 {
		t.Errorf("report: %+v", rep)
	}
}

func TestAccountWithoutHRRecordIsLowAndNamedAsSuch(t *testing.T) {
	emps := []platform.Employee{{ID: "e1", WorkEmail: "hal@acme.io", Status: platform.EmploymentActive}}
	ws := operate.Workspace{Provider: "m365", Users: []operate.User{
		{Email: "hal@acme.io"},
		{Email: "svc-backup@acme.io"},
		{Email: "old-contractor@acme.io", Suspended: true}, // suspended + unknown: nothing to do
	}}
	fs, rep := Correlate(emps, ws, opts())
	if len(fs) != 1 || fs[0].RuleID != "hris::account-without-hr-record" || fs[0].Severity != types.SeverityLow || fs[0].Endpoint != "svc-backup@acme.io" {
		t.Fatalf("got %s", rules(fs))
	}
	if strings.Contains(strings.ToLower(fs[0].Description), "rogue") || !strings.Contains(fs[0].Description, "service account") {
		t.Errorf("the finding says 'no record' and names the legitimate explanations, never 'rogue': %s", fs[0].Description)
	}
	if rep.Unmatched != 1 || rep.Matched != 1 {
		t.Errorf("report: %+v", rep)
	}
}

func TestEmptyInputsRefuseToConcludeAndSaySo(t *testing.T) {
	ws := operate.Workspace{Provider: "okta", Users: []operate.User{{Email: "x@acme.io"}}}
	fs, rep := Correlate(nil, ws, opts())
	if len(fs) != 0 || len(rep.ChecksNotRun) != 1 || !strings.Contains(rep.ChecksNotRun[0], "no employee records") {
		t.Fatalf("an empty roster is not a clean process: %s %+v", rules(fs), rep)
	}
	fs, rep = Correlate([]platform.Employee{{ID: "e1", WorkEmail: "x@acme.io"}}, operate.Workspace{}, opts())
	if len(fs) != 0 || len(rep.ChecksNotRun) != 1 || !strings.Contains(rep.ChecksNotRun[0], "no identity-provider accounts") {
		t.Fatalf("no accounts → say so: %+v", rep)
	}
	fs, rep = Correlate([]platform.Employee{{ID: "e1", Name: "No Email", Status: platform.EmploymentTerminated}}, ws, opts())
	if len(fs) != 0 || len(rep.ChecksNotRun) != 1 || !strings.Contains(rep.ChecksNotRun[0], "no email addresses") {
		t.Fatalf("a roster without addresses cannot join and must say so: %s %+v", rules(fs), rep)
	}
}

func TestACleanEstateYieldsNothing(t *testing.T) {
	emps := []platform.Employee{
		{ID: "e1", WorkEmail: "a@acme.io", Status: platform.EmploymentActive},
		{ID: "e2", WorkEmail: "b@acme.io", Status: platform.EmploymentTerminated, EndDate: "2026-01-01"},
	}
	ws := operate.Workspace{Provider: "okta", Users: []operate.User{{Email: "a@acme.io"}, {Email: "b@acme.io", Suspended: true}}}
	fs, rep := Correlate(emps, ws, opts())
	if len(fs) != 0 {
		t.Fatalf("grounded: a correct estate produces zero findings, got %s", rules(fs))
	}
	if rep.LeaversDeprovisioned != 1 || len(rep.ChecksNotRun) != 0 {
		t.Errorf("and the report records the success: %+v", rep)
	}
}

func TestNormalizeStatusNeverGuesses(t *testing.T) {
	for in, want := range map[string]string{
		"ACTIVE": platform.EmploymentActive, "Inactive": platform.EmploymentTerminated, "PENDING": platform.EmploymentPending,
		"terminated": platform.EmploymentTerminated, "on_leave": platform.EmploymentUnknown, "": platform.EmploymentUnknown,
	} {
		if got := NormalizeStatus(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

// --- Merge ---

func TestMergeFetchMapsAndFollowsCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mkey" || r.Header.Get("X-Account-Token") != "acct" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"detail":"Authentication credentials were not provided."}`)
			return
		}
		if r.URL.Path != "/api/hris/v1/employees" {
			w.WriteHeader(404)
			return
		}
		if r.URL.Query().Get("expand") != "employments" {
			t.Errorf("must expand employments to read the type; got %s", r.URL.RawQuery)
		}
		if r.URL.Query().Get("cursor") == "c2" {
			fmt.Fprint(w, `{"next":null,"results":[{"id":"m3","display_full_name":"Ivy Intern","work_email":"ivy@acme.io","employment_status":"PENDING","start_date":"2026-10-01T00:00:00Z","employments":["emp-id-only"]}]}`)
			return
		}
		fmt.Fprint(w, `{"next":"c2","results":[
		  {"id":"m1","first_name":"Alice","last_name":"Leaver","work_email":"alice@acme.io","personal_email":"al@home.example","employment_status":"INACTIVE","start_date":"2021-03-01T00:00:00Z","termination_date":"2026-06-15T00:00:00Z","employments":[{"employment_type":"FULL_TIME"}]},
		  {"id":"m2","display_full_name":"Con Tractor","work_email":"con@acme.io","employment_status":"ACTIVE","employments":[{"employment_type":"CONTRACTOR"}]}
		]}`)
	}))
	defer srv.Close()
	m := &Merge{BaseURL: srv.URL, APIKey: "mkey", AccountToken: "acct", HTTP: srv.Client(), Now: func() time.Time { return fixedNow }}
	emps, rep, err := m.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Employees != 3 || len(emps) != 3 {
		t.Fatalf("cursor must be followed: %+v", rep)
	}
	a := emps[0]
	if a.Name != "Alice Leaver" || a.Status != platform.EmploymentTerminated || a.EndDate != "2026-06-15" || a.StartDate != "2021-03-01" || a.EmploymentType != "full_time" || len(a.PersonalEmails) != 1 {
		t.Errorf("alice: %+v", a)
	}
	if emps[1].EmploymentType != "contractor" || emps[1].Status != platform.EmploymentActive {
		t.Errorf("con: %+v", emps[1])
	}
	if emps[2].Status != platform.EmploymentPending || emps[2].EmploymentType != "" {
		t.Errorf("ivy: pending, and an unexpanded employment yields no type rather than a guess: %+v", emps[2])
	}
	for _, e := range emps {
		if e.Source != platform.HRISMerge || !e.FetchedAt.Equal(fixedNow) {
			t.Errorf("provenance: %+v", e)
		}
	}
	if _, _, err := (&Merge{BaseURL: srv.URL, APIKey: "bad", AccountToken: "acct", HTTP: srv.Client()}).Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad key → 401 error, got %v", err)
	}
}

// --- Finch ---

func TestFinchFetchJoinsDirectoryIndividualAndEmployment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ftok" {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("Finch-API-Version") == "" {
			t.Error("Finch requires the version header")
		}
		switch r.URL.Path {
		case "/employer/directory":
			if r.URL.Query().Get("offset") != "0" {
				fmt.Fprint(w, `{"paging":{"count":3,"offset":250},"individuals":[]}`)
				return
			}
			fmt.Fprint(w, `{"paging":{"count":3,"offset":0},"individuals":[
			  {"id":"i1","first_name":"Alice","last_name":"Leaver","is_active":false,"department":{"name":"Eng"}},
			  {"id":"i2","first_name":"Bob","last_name":"Current","is_active":true},
			  {"id":"i3","first_name":"New","last_name":"Hire","is_active":false}
			]}`)
		case "/employer/individual", "/employer/employment":
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Requests []struct {
					ID string `json:"individual_id"`
				} `json:"requests"`
			}
			_ = json.Unmarshal(body, &req)
			if len(req.Requests) != 3 {
				t.Errorf("batch must carry every directory id, got %s", body)
			}
			if r.URL.Path == "/employer/individual" {
				fmt.Fprint(w, `{"responses":[
				  {"individual_id":"i1","code":200,"body":{"emails":[{"data":"alice@acme.io","type":"work"},{"data":"al@home.example","type":"personal"}]}},
				  {"individual_id":"i2","code":200,"body":{"emails":[{"data":"bob@acme.io","type":"work"}]}},
				  {"individual_id":"i3","code":200,"body":{"emails":[{"data":"new@acme.io","type":"work"}]}}
				]}`)
				return
			}
			fmt.Fprint(w, `{"responses":[
			  {"individual_id":"i1","code":200,"body":{"start_date":"2020-01-06","end_date":"2026-06-15","is_active":false,"employment":{"type":"employee","subtype":"full_time"}}},
			  {"individual_id":"i2","code":200,"body":{"start_date":"2022-05-02","is_active":true,"employment":{"type":"contractor"}}},
			  {"individual_id":"i3","code":200,"body":{"start_date":"2026-10-01","is_active":false,"employment":{"type":"employee"}}}
			]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	f := &Finch{BaseURL: srv.URL, Token: "ftok", HTTP: srv.Client(), Now: func() time.Time { return fixedNow }}
	emps, rep, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Employees != 3 || len(rep.Unread) != 0 {
		t.Fatalf("report: %+v", rep)
	}
	a := emps[0]
	if a.WorkEmail != "alice@acme.io" || len(a.PersonalEmails) != 1 || a.Status != platform.EmploymentTerminated || a.EndDate != "2026-06-15" || a.EmploymentType != "employee" || a.Department != "Eng" {
		t.Errorf("alice: %+v", a)
	}
	if emps[1].Status != platform.EmploymentActive || emps[1].EmploymentType != "contractor" {
		t.Errorf("bob: %+v", emps[1])
	}
	if emps[2].Status != platform.EmploymentPending {
		t.Errorf("inactive with a future start is PENDING, not a leaver: %+v", emps[2])
	}
	// End to end: the fetched roster correlates.
	ws := operate.Workspace{Provider: "okta", Users: []operate.User{{Email: "alice@acme.io"}, {Email: "bob@acme.io"}, {Email: "new@acme.io"}}}
	fs, _ := Correlate(emps, ws, opts())
	if len(fs) != 1 || fs[0].Endpoint != "alice@acme.io" {
		t.Fatalf("only alice is a leaver with access; a pending hire's pre-provisioned account is fine: %s", rules(fs))
	}
}

func TestFinchUnreadIndividualIsNamedNotDropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/employer/directory":
			fmt.Fprint(w, `{"paging":{"count":1,"offset":0},"individuals":[{"id":"i1","first_name":"Quiet","last_name":"One","is_active":false}]}`)
		case "/employer/individual":
			fmt.Fprint(w, `{"responses":[{"individual_id":"i1","code":403,"body":{}}]}`)
		case "/employer/employment":
			fmt.Fprint(w, `{"responses":[{"individual_id":"i1","code":200,"body":{"end_date":"2026-01-01"}}]}`)
		}
	}))
	defer srv.Close()
	emps, rep, err := (&Finch{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(emps) != 1 || emps[0].WorkEmail != "" || rep.WithoutEmail != 1 || len(rep.Unread) != 1 || rep.Unread[0] != "Quiet One" {
		t.Fatalf("kept, with the gap named: %+v %+v", emps, rep)
	}
}

func TestNewRefusesUnusableConfigs(t *testing.T) {
	open := func(ref string) (string, error) {
		if strings.HasPrefix(ref, "ok:") {
			return strings.TrimPrefix(ref, "ok:"), nil
		}
		return "", fmt.Errorf("unknown ref")
	}
	for name, cfg := range map[string]*platform.HRISConfig{
		"nil":               nil,
		"unknown":           {Provider: "bamboohr", KeyRef: "ok:k"},
		"merge half":        {Provider: platform.HRISMerge, KeyRef: "ok:k"},
		"merge bad account": {Provider: platform.HRISMerge, KeyRef: "ok:k", AccountTokenRef: "bad"},
		"finch nothing":     {Provider: platform.HRISFinch},
	} {
		if _, err := New(cfg, Options{Open: open}); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if f, err := New(&platform.HRISConfig{Provider: platform.HRISMerge, KeyRef: "ok:k", AccountTokenRef: "ok:a"}, Options{Open: open, MergeBase: "https://m.example"}); err != nil || f.(*Merge).AccountToken != "a" || f.(*Merge).BaseURL != "https://m.example" {
		t.Errorf("merge: %v", err)
	}
	if f, err := New(&platform.HRISConfig{Provider: platform.HRISFinch, KeyRef: "ok:t", BaseURL: "https://own.example"}, Options{Open: open, FinchBase: "https://f.example"}); err != nil || f.(*Finch).Token != "t" || f.(*Finch).BaseURL != "https://own.example" {
		t.Errorf("finch: the config's own base wins over the default: %v", err)
	}
}

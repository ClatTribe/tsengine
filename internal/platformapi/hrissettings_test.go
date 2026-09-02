package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func hrisDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	vault, err := secret.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st, Vault: vault}
}

func putHRIS(d Deps, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/v1/settings/hris", strings.NewReader(body))
	rec := httptest.NewRecorder()
	d.handlePutHRISSettings(rec, req, "ten-1")
	return rec
}

func TestHRISSettings_SealsRedactsRefuses(t *testing.T) {
	d := hrisDeps(t)
	rec := putHRIS(d, `{"provider":"merge","api_key":"mk-secret","account_token":"at-secret"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"has_key":true`) || !strings.Contains(rec.Body.String(), `"has_account_token":true`) {
		t.Errorf("got %s", rec.Body.String())
	}
	tn, _ := d.Store.GetTenant(context.Background(), "ten-1")
	if tn.HRIS == nil || strings.Contains(tn.HRIS.KeyRef, "mk-secret") || tn.Redacted().HRIS != nil {
		t.Errorf("sealed + redacted: %+v", tn.HRIS)
	}
	for name, body := range map[string]string{
		"unknown":       `{"provider":"bamboohr","api_key":"k"}`,
		"merge half":    `{"provider":"finch"}`,
		"merge no acct": `{"provider":"merge","api_key":"k"}`,
	} {
		d2 := hrisDeps(t)
		if rec := putHRIS(d2, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

type fakeWS struct{ ws operate.Workspace }

func (f fakeWS) Workspace(context.Context, platform.Asset) (operate.Workspace, error) {
	return f.ws, nil
}

type hrisSubmitter struct{ acts []platform.Action }

func (c *hrisSubmitter) Submit(_ context.Context, a platform.Action) (platform.Action, error) {
	c.acts = append(c.acts, a)
	return a, nil
}

// The whole loop through the on-demand door: fetch the roster from a fake Merge, store it, join it
// against the Okta workspace, store the leaver finding, stamp the source, and — because the join
// proposes against the WORKSPACE asset — reach the desk as a HITL-gated account suspend rather than
// a generic ticket.
func TestSyncHRIS_FetchesJoinsStoresAndProposesGatedSuspend(t *testing.T) {
	d := hrisDeps(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mk" || r.Header.Get("X-Account-Token") != "at" {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `{"next":null,"results":[
		  {"id":"m1","display_full_name":"Alice Leaver","work_email":"alice@acme.io","employment_status":"INACTIVE","termination_date":"2026-06-15T00:00:00Z"},
		  {"id":"m2","display_full_name":"Bob Current","work_email":"bob@acme.io","employment_status":"ACTIVE"}
		]}`)
	}))
	defer srv.Close()
	k, _ := d.Vault.Seal("mk")
	a, _ := d.Vault.Seal("at")
	tn, _ := d.Store.GetTenant(context.Background(), "ten-1")
	tn.HRIS = &platform.HRISConfig{Provider: platform.HRISMerge, KeyRef: k, AccountTokenRef: a}
	_ = d.Store.PutTenant(context.Background(), tn)
	_ = d.Store.PutConnection(context.Background(), platform.Connection{ID: "conn-okta", TenantID: "ten-1", Kind: platform.ConnOkta, Status: platform.ConnActive})
	_ = d.Store.PutAsset(context.Background(), platform.Asset{ID: "ws-1", TenantID: "ten-1", Type: runner.WorkspaceType, Target: "acme.okta.com", ConnectionID: "conn-okta", Meta: map[string]string{"provider": platform.ConnOkta}})
	d.HRISHTTP, d.MergeAPIBase = srv.Client(), srv.URL
	d.WorkspaceSource = fakeWS{operate.Workspace{Provider: "okta", Users: []operate.User{
		{Email: "alice@acme.io", Admin: true, MFA: true},
		{Email: "bob@acme.io", MFA: true},
	}}}
	sub := &hrisSubmitter{}
	d.Submitter = sub
	d.ProposeFix = func(f types.Finding, as platform.Asset) (platform.Action, bool) {
		return remediate.Propose(f, as, func() string { return "x" })
	}

	rec := httptest.NewRecorder()
	d.handleSyncHRIS(rec, httptest.NewRequest(http.MethodPost, "/v1/hris/sync", nil), "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Provider       string   `json:"provider"`
		Employees      int      `json:"employees"`
		IssuesDetected int      `json:"issues_detected"`
		Joined         bool     `json:"joined"`
		ChecksNotRun   []string `json:"checks_not_run"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Provider != "merge" || resp.Employees != 2 || resp.IssuesDetected != 1 || !resp.Joined || len(resp.ChecksNotRun) != 0 {
		t.Fatalf("resp: %+v", resp)
	}
	emps, _ := d.Store.ListEmployees(context.Background(), "ten-1")
	if len(emps) != 2 || emps[0].TenantID != "ten-1" {
		t.Errorf("roster must be stored under the tenant: %+v", emps)
	}
	stored, _ := d.Store.ListFindings(context.Background(), "ten-1", store.FindingFilter{})
	if len(stored) != 1 || stored[0].RuleID != "hris::leaver-with-active-account" || stored[0].Severity != types.SeverityCritical {
		t.Fatalf("alice (admin leaver) must be a stored critical finding: %+v", stored)
	}
	tn, _ = d.Store.GetTenant(context.Background(), "ten-1")
	if _, ok := tn.PostureAssessed["hris"]; !ok {
		t.Error("the sync must stamp the posture source")
	}
	if len(sub.acts) != 1 {
		t.Fatalf("one action must reach the desk, got %d", len(sub.acts))
	}
	act := sub.acts[0]
	if act.Kind != platform.ActApplyConfig || act.Payload["remediation_type"] != "account_suspend" || act.Payload["target"] != "alice@acme.io" || act.ConnectionID != "conn-okta" {
		t.Errorf("a leaver on Okta must propose the gated live suspend against the Okta connection, got kind=%s tier=%d payload=%+v conn=%s", act.Kind, act.Tier, act.Payload, act.ConnectionID)
	}
	if !act.NeedsApproval() {
		t.Error("the suspend must be human-gated")
	}
}

// No identity provider connected: the roster is stored, joined=false, and the response SAYS why —
// a stored-but-unjoined roster must not read as "no leavers with access".
func TestSyncHRIS_NoWorkspaceIsStoredButNotJoined(t *testing.T) {
	d := hrisDeps(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/employer/directory":
			fmt.Fprint(w, `{"paging":{"count":1,"offset":0},"individuals":[{"id":"i1","first_name":"A","last_name":"B","is_active":false}]}`)
		case "/employer/individual":
			fmt.Fprint(w, `{"responses":[{"individual_id":"i1","code":200,"body":{"emails":[{"data":"a@acme.io","type":"work"}]}}]}`)
		case "/employer/employment":
			fmt.Fprint(w, `{"responses":[{"individual_id":"i1","code":200,"body":{"end_date":"2026-01-01"}}]}`)
		}
	}))
	defer srv.Close()
	k, _ := d.Vault.Seal("ft")
	tn, _ := d.Store.GetTenant(context.Background(), "ten-1")
	tn.HRIS = &platform.HRISConfig{Provider: platform.HRISFinch, KeyRef: k}
	_ = d.Store.PutTenant(context.Background(), tn)
	d.HRISHTTP, d.FinchAPIBase = srv.Client(), srv.URL
	d.WorkspaceSource = fakeWS{}

	rec := httptest.NewRecorder()
	d.handleSyncHRIS(rec, httptest.NewRequest(http.MethodPost, "/v1/hris/sync", nil), "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"joined":false`) || !strings.Contains(body, "no identity provider is connected") {
		t.Errorf("must say the join did not run and why: %s", body)
	}
	emps, _ := d.Store.ListEmployees(context.Background(), "ten-1")
	if len(emps) != 1 || emps[0].Status != platform.EmploymentTerminated {
		t.Errorf("roster still stored: %+v", emps)
	}
	if stored, _ := d.Store.ListFindings(context.Background(), "ten-1", store.FindingFilter{}); len(stored) != 0 {
		t.Errorf("nothing to join against → no findings: %+v", stored)
	}
	// GET reflects the stored roster.
	rec = httptest.NewRecorder()
	d.handleGetHRISSettings(rec, httptest.NewRequest(http.MethodGet, "/v1/settings/hris", nil), "ten-1")
	if !strings.Contains(rec.Body.String(), `"employees":1`) || !strings.Contains(rec.Body.String(), `"last_synced_at"`) {
		t.Errorf("GET: %s", rec.Body.String())
	}
}

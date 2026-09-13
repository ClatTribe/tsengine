package identitylog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/identitythreat"
)

// Fixtures are the providers' documented response shapes. Each test drives the REAL fetcher over an
// httptest server and then the REAL detector over what came out, because the value of this package
// is the join: a provider log in, a detection out. The fake servers use a plain http.Client since the
// production one refuses loopback by design.

func TestOkta_SystemLogBecomesEventsAndAPasswordSprayIsDetected(t *testing.T) {
	var pages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no token", 401)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/v1/logs") {
			http.NotFound(w, r)
			return
		}
		pages++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("after") == "p2" || pages > 1 {
			w.Header().Set("Link", `<`+"http://"+r.Host+`/api/v1/logs?after=p3>; rel="next"`)
			w.Write([]byte(`[]`)) // the stream's empty tail — Okta always returns a next link
			return
		}
		w.Header().Set("Link", `<`+"http://"+r.Host+`/api/v1/logs?after=p2>; rel="next"`)
		var b strings.Builder
		b.WriteString("[")
		// six failed sign-ins for one user from one IP inside ten minutes → password_spray
		for i := 0; i < 6; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`{"uuid":"f` + string(rune('0'+i)) + `","published":"2026-09-13T10:0` + string(rune('0'+i)) + `:00.000Z","eventType":"user.session.start",
			  "outcome":{"result":"FAILURE","reason":"INVALID_CREDENTIALS"},"actor":{"alternateId":"Ada@Acme.io","type":"User"},
			  "client":{"ipAddress":"203.0.113.9","geographicalContext":{"country":"Brazil"}},"target":[]}`)
		}
		b.WriteString(`,{"uuid":"s1","published":"2026-09-13T10:07:00.000Z","eventType":"user.session.start","outcome":{"result":"SUCCESS"},
		  "actor":{"alternateId":"ada@acme.io","type":"User"},"client":{"ipAddress":"203.0.113.9","geographicalContext":{"country":"Brazil"}},"target":[]}`)
		b.WriteString(`,{"uuid":"g1","published":"2026-09-13T10:08:00.000Z","eventType":"user.account.privilege.grant","outcome":{"result":"SUCCESS"},
		  "actor":{"alternateId":"admin@acme.io","type":"User"},"client":{"ipAddress":"198.51.100.2"},
		  "target":[{"type":"User","alternateId":"bob@acme.io"},{"type":"ROLE","displayName":"Super Organization Administrator"}]}`)
		b.WriteString(`,{"uuid":"m1","published":"2026-09-13T10:09:00.000Z","eventType":"user.mfa.factor.deactivate","outcome":{"result":"SUCCESS"},
		  "actor":{"alternateId":"admin@acme.io","type":"User"},"target":[{"type":"User","alternateId":"bob@acme.io"}]}`)
		b.WriteString(`,{"uuid":"p1","published":"2026-09-13T10:09:30.000Z","eventType":"system.push.send_factor_verify_push","outcome":{"result":"SUCCESS"},
		  "actor":{"alternateId":"bob@acme.io","type":"User"},"target":[{"type":"User","alternateId":"bob@acme.io"}]}`)
		b.WriteString(`,{"uuid":"x1","published":"2026-09-13T10:10:00.000Z","eventType":"application.lifecycle.update","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"admin@acme.io"}}`)
		b.WriteString("]")
		w.Write([]byte(b.String()))
	}))
	defer srv.Close()

	o := &Okta{OrgURL: srv.URL, HTTP: srv.Client()}
	rep, err := o.Fetch(context.Background(), "tok", time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fetched != 11 || len(rep.Events) != 10 {
		t.Fatalf("fetched %d, mapped %d events; want 11 / 10 (one unmapped)", rep.Fetched, len(rep.Events))
	}
	if rep.Unmapped["application.lifecycle.update"] != 1 {
		t.Errorf("the unmapped type must be COUNTED, got %v", rep.Unmapped)
	}
	kinds := map[identitythreat.EventType]int{}
	for _, e := range rep.Events {
		kinds[e.Type]++
		if e.User != strings.ToLower(e.User) {
			t.Errorf("user not normalised: %q", e.User)
		}
	}
	if kinds[identitythreat.EventLoginFail] != 6 || kinds[identitythreat.EventLogin] != 1 || kinds[identitythreat.EventRoleGrant] != 1 ||
		kinds[identitythreat.EventMFARemoved] != 1 || kinds[identitythreat.EventMFAChallenge] != 1 {
		t.Errorf("event kinds: %v", kinds)
	}
	for _, e := range rep.Events {
		if e.Type == identitythreat.EventRoleGrant && (e.User != "bob@acme.io" || !e.Admin) {
			t.Errorf("role grant must be about the TARGET user and flag the admin role: %+v", e)
		}
		if e.Type == identitythreat.EventMFARemoved && e.User != "bob@acme.io" {
			t.Errorf("MFA removal must be about the target user, not the admin who acted: %+v", e)
		}
	}

	threats := identitythreat.Detect(rep.Events, identitythreat.Config{})
	rules := map[string]bool{}
	for _, th := range threats {
		rules[th.Rule] = true
	}
	for _, want := range []string{"password_spray", "spray_success", "privileged_grant", "mfa_removed"} {
		if !rules[want] {
			t.Errorf("the detector did not fire %s over the Okta log; fired %v", want, rules)
		}
	}
	if pages != 2 {
		t.Errorf("the read should stop on the first EMPTY page (Okta always sends a next link), made %d requests", pages)
	}
}

func TestOkta_ANonLogPageIsAnErrorNotAnEmptyWindow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>Sign in to Okta</html>"))
	}))
	defer srv.Close()
	o := &Okta{OrgURL: srv.URL, HTTP: srv.Client()}
	if _, err := o.Fetch(context.Background(), "expired", time.Now().Add(-time.Hour)); err == nil {
		t.Fatal("an HTML page behind an expired token read as an empty log — on a detector that is 'no attack'")
	}
}

func TestM365_SignInsAndDirectoryAuditsBecomeEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/auditLogs/signIns"):
			if r.URL.Query().Get("$skiptoken") == "" {
				w.Write([]byte(`{"value":[
				 {"id":"a","createdDateTime":"2026-09-13T10:00:00Z","userPrincipalName":"Ada@acme.io","ipAddress":"203.0.113.9","status":{"errorCode":0},"location":{"countryOrRegion":"BR"}},
				 {"id":"b","createdDateTime":"2026-09-13T10:30:00Z","userPrincipalName":"ada@acme.io","ipAddress":"198.51.100.7","status":{"errorCode":0},"location":{"countryOrRegion":"JP"}},
				 {"id":"c","createdDateTime":"2026-09-13T10:31:00Z","userPrincipalName":"cy@acme.io","ipAddress":"198.51.100.7","status":{"errorCode":50126,"failureReason":"Invalid username or password"},"location":{"countryOrRegion":"JP"}}
				],"@odata.nextLink":"http://` + r.Host + `/v1.0/auditLogs/signIns?$skiptoken=x"}`))
			} else {
				w.Write([]byte(`{"value":[]}`))
			}
		case strings.HasSuffix(r.URL.Path, "/auditLogs/directoryAudits"):
			w.Write([]byte(`{"value":[
			 {"id":"d1","activityDateTime":"2026-09-13T11:00:00Z","activityDisplayName":"Add member to role","result":"success",
			  "initiatedBy":{"user":{"userPrincipalName":"admin@acme.io","ipAddress":"198.51.100.2"}},
			  "targetResources":[{"type":"User","userPrincipalName":"bob@acme.io","modifiedProperties":[{"displayName":"Role.DisplayName","newValue":"\"Global Administrator\""}]}]},
			 {"id":"d2","activityDateTime":"2026-09-13T11:01:00Z","activityDisplayName":"Admin deleted security info","result":"success",
			  "initiatedBy":{"user":{"userPrincipalName":"admin@acme.io"}},"targetResources":[{"type":"User","userPrincipalName":"bob@acme.io"}]},
			 {"id":"d3","activityDateTime":"2026-09-13T11:02:00Z","activityDisplayName":"Update application","result":"success","targetResources":[]}
			]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	m := &M365{GraphBase: srv.URL + "/v1.0", HTTP: srv.Client()}
	rep, err := m.Fetch(context.Background(), "tok", time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fetched != 6 || len(rep.Events) != 5 || rep.Unmapped["Update application"] != 1 {
		t.Fatalf("fetched %d mapped %d unmapped %v", rep.Fetched, len(rep.Events), rep.Unmapped)
	}
	var grant, removed bool
	for _, e := range rep.Events {
		if e.Type == identitythreat.EventRoleGrant && e.User == "bob@acme.io" && e.Admin && e.Detail == "Global Administrator" {
			grant = true
		}
		if e.Type == identitythreat.EventMFARemoved && e.User == "bob@acme.io" {
			removed = true
		}
	}
	if !grant || !removed {
		t.Errorf("directory audits not mapped: grant=%v removed=%v events=%+v", grant, removed, rep.Events)
	}
	if _, ok := rep.ChecksNotRun["mfa_fatigue"]; !ok {
		t.Error("the report must declare that Graph cannot feed the MFA-fatigue rule")
	}
	// Two countries within an hour for ada → impossible travel, from real Graph fields.
	rules := map[string]bool{}
	for _, th := range identitythreat.Detect(rep.Events, identitythreat.Config{}) {
		rules[th.Rule] = true
	}
	if !rules["impossible_travel"] || !rules["privileged_grant"] {
		t.Errorf("expected impossible_travel and privileged_grant, fired %v", rules)
	}
}

func TestGWorkspace_LoginAndAdminReportsBecomeEventsAndDeclareNoCountry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/applications/login"):
			w.Write([]byte(`{"kind":"admin#reports#activities","items":[
			 {"id":{"time":"2026-09-13T10:00:00.000Z","uniqueQualifier":"1","applicationName":"login"},"actor":{"email":"Ada@acme.io"},"ipAddress":"203.0.113.9",
			  "events":[{"name":"login_failure","parameters":[{"name":"login_failure_type","value":"login_failure_invalid_password"}]}]},
			 {"id":{"time":"2026-09-13T10:01:00.000Z","uniqueQualifier":"2","applicationName":"login"},"actor":{"email":"ada@acme.io"},"ipAddress":"203.0.113.9",
			  "events":[{"name":"login_success","parameters":[]},{"name":"login_challenge","parameters":[{"name":"login_challenge_method","value":"idv_preregistered_phone"}]}]}
			]}`))
		case strings.HasSuffix(r.URL.Path, "/applications/admin"):
			w.Write([]byte(`{"kind":"admin#reports#activities","items":[
			 {"id":{"time":"2026-09-13T11:00:00.000Z","uniqueQualifier":"3","applicationName":"admin"},"actor":{"email":"admin@acme.io"},"ipAddress":"198.51.100.2",
			  "events":[{"name":"ASSIGN_ROLE","parameters":[{"name":"ROLE_NAME","value":"_SEED_ADMIN_ROLE"},{"name":"USER_EMAIL","value":"bob@acme.io"}]},
			            {"name":"CHANGE_APPLICATION_SETTING","parameters":[]}]}
			]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	g := &GWorkspace{APIBase: srv.URL, HTTP: srv.Client()}
	rep, err := g.Fetch(context.Background(), "tok", time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fetched != 5 || len(rep.Events) != 4 || rep.Unmapped["admin:CHANGE_APPLICATION_SETTING"] != 1 {
		t.Fatalf("fetched %d mapped %d unmapped %v", rep.Fetched, len(rep.Events), rep.Unmapped)
	}
	var grant bool
	for _, e := range rep.Events {
		if e.Country != "" {
			t.Errorf("Google reports carry no country; one was invented: %+v", e)
		}
		if e.Type == identitythreat.EventRoleGrant && e.User == "bob@acme.io" && e.Admin {
			grant = true
		}
	}
	if !grant {
		t.Errorf("ASSIGN_ROLE must become a privileged grant about USER_EMAIL: %+v", rep.Events)
	}
	if _, ok := rep.ChecksNotRun["impossible_travel"]; !ok {
		t.Error("the report must declare that impossible travel cannot be evaluated without a country")
	}
}

func TestSinceForAndMerge(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	if got := SinceFor(time.Time{}, now); !got.Equal(now.Add(-Window)) {
		t.Errorf("no cursor → Window ago, got %v", got)
	}
	if got := SinceFor(now.Add(-2*time.Hour), now); !got.Equal(now.Add(-3 * time.Hour)) {
		t.Errorf("cursor → cursor minus overlap, got %v", got)
	}
	if got := SinceFor(now.Add(-72*time.Hour), now); !got.Equal(now.Add(-Window)) {
		t.Errorf("an old cursor is floored at the window, got %v", got)
	}
	a := Report{Provider: "okta", Events: []identitythreat.Event{{ID: "1", Time: now}, {ID: "2", Time: now.Add(-time.Minute)}}}
	b := Report{Provider: "okta", Events: []identitythreat.Event{{ID: "2", Time: now.Add(-time.Minute)}, {ID: "3", Time: now.Add(-2 * time.Minute)}}}
	got := Merge(a, b)
	if len(got) != 3 || got[0].ID != "3" || got[2].ID != "1" {
		t.Errorf("merge must dedupe by id and sort oldest first: %+v", got)
	}
	if !Latest(a).Equal(now) || !Latest(Report{}).IsZero() {
		t.Error("Latest must be the newest event time, zero for an empty read")
	}
}

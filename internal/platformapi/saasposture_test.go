package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

func saasHandler(t *testing.T) (interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}, store.Store) {
	t.Helper()
	st := store.NewMemory()
	n := 0
	// deterministic, collision-free ids (prod sets a random-hex NewID; the unset fallback is
	// time-based and collides in a tight loop).
	newID := func() string { n++; return fmt.Sprintf("%04d", n) }
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", NewID: newID})
	return h, st
}

func TestSaaSSnapshot_ZoomMisconfigStoresFindings(t *testing.T) {
	h, st := saasHandler(t)
	// a Zoom account with several gaps → findings
	snap := `{"name":"acme","two_factor_required":false,"sso_enforced":false,
		"meeting_passcode_required":false,"waiting_room_enabled":false,
		"cloud_recording_encrypted":false,"recording_auto_delete":false,"approved_apps_only":false}`
	rec := do(h, "POST", "/v1/saas/zoom/snapshot", "t1", snap)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Provider         string `json:"provider"`
		FindingsDetected int    `json:"findings_detected"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Provider != "zoom" || out.FindingsDetected == 0 {
		t.Fatalf("expected zoom findings, got %+v", out)
	}
	// findings must land in the store (so they flow into issues/grc/hitl)
	stored, err := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != out.FindingsDetected {
		t.Errorf("stored %d findings, endpoint reported %d", len(stored), out.FindingsDetected)
	}
	if len(stored) > 0 && stored[0].Tool != "sspm" {
		t.Errorf("finding tool should be sspm, got %q", stored[0].Tool)
	}
}

func TestSaaSSnapshot_HardenedYieldsZero(t *testing.T) {
	h, st := saasHandler(t)
	// a fully hardened Slack workspace → zero findings (the testability invariant, end to end)
	snap := `{"name":"acme","two_factor_required":true,"sso_enforced":true,"approved_apps_only":true,
		"public_link_sharing":false,"invite_domain_allowlist":true}`
	rec := do(h, "POST", "/v1/saas/slack/snapshot", "t1", snap)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"findings_detected":0`) {
		t.Errorf("a hardened workspace must yield 0 findings, got: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"findings":[]`) {
		t.Errorf("zero findings must serialize as [] not null, got: %s", rec.Body.String())
	}
	if got, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{}); len(got) != 0 {
		t.Errorf("nothing should be stored for a hardened app, got %d", len(got))
	}
}

func TestSaaSSnapshot_UnknownProviderIs400(t *testing.T) {
	h, _ := saasHandler(t)
	rec := do(h, "POST", "/v1/saas/notarealapp/snapshot", "t1", `{}`)
	if rec.Code != 400 {
		t.Errorf("unknown provider must be 400, got %d", rec.Code)
	}
}

func TestSaaSSnapshot_AllFiveProvidersRoute(t *testing.T) {
	h, _ := saasHandler(t)
	for _, p := range []string{"github_org", "slack", "zoom", "atlassian", "salesforce"} {
		rec := do(h, "POST", "/v1/saas/"+p+"/snapshot", "t1", `{"name":"x","login":"x"}`)
		if rec.Code != 200 {
			t.Errorf("provider %q should route (200), got %d: %s", p, rec.Code, rec.Body.String())
		}
	}
}

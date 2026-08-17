package sspm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// fakeGraph serves the four Graph endpoints FetchM365Posture reads. Any endpoint whose
// body is absent from the map answers 403, which is how a real tenant behaves when the
// app registration lacks that scope or the feature is unlicensed.
func fakeGraph(t *testing.T, bodies map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("missing/incorrect bearer auth: %q", got)
		}
		for suffix, body := range bodies {
			if strings.HasSuffix(r.URL.Path, suffix) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
	}))
}

// A wide-open tenant must be read faithfully and then produce the SCuBA findings.
func TestFetchM365Posture_ReadsInsecureTenantAndAssesses(t *testing.T) {
	srv := fakeGraph(t, map[string]string{
		"/admin/sharepoint/settings": `{
			"sharingCapability":"externalUserAndGuestSharing",
			"oneDriveSharingCapability":"externalUserAndGuestSharing",
			"sharingDomainRestrictionMode":"none",
			"defaultSharingLinkType":"anonymousAccess",
			"defaultLinkPermission":"edit",
			"anonymousLinkExpirationRestrictionDays":0}`,
		"/policies/authenticationMethodsPolicy": `{"authenticationMethodConfigurations":[
			{"id":"Sms","state":"enabled"},{"id":"Fido2","state":"enabled"}]}`,
		"/policies/authorizationPolicy": `{"defaultUserRolePermissions":{"allowedToCreateApps":true}}`,
		// CA policy list read successfully but contains no high-risk blocking policy.
		"/identity/conditionalAccess/policies": `{"value":[
			{"state":"enabled","conditions":{"signInRiskLevels":["medium"]},"grantControls":{"builtInControls":["mfa"]}}]}`,
	})
	defer srv.Close()

	snap, err := FetchM365Posture(context.Background(), srv.URL, "contoso", "tok", srv.Client())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if snap.SharePointSharing != "anonymous" || snap.OneDriveSharing != "anonymous" {
		t.Errorf("sharing level: got %q/%q, want anonymous/anonymous", snap.SharePointSharing, snap.OneDriveSharing)
	}
	if !snap.AnyoneLinksNeverExpire {
		t.Error("anonymousLinkExpirationRestrictionDays=0 means links never expire")
	}
	if snap.DefaultSharingScope != "anyone" || snap.DefaultLinkPermission != "edit" {
		t.Errorf("link defaults: got %q/%q", snap.DefaultSharingScope, snap.DefaultLinkPermission)
	}
	if !snap.WeakMFAMethodsEnabled {
		t.Error("SMS enabled must set WeakMFAMethodsEnabled")
	}
	if !snap.UserAppRegistrationAllowed {
		t.Error("allowedToCreateApps=true must set UserAppRegistrationAllowed")
	}
	if !snap.RiskyUserBlockDisabled || !snap.RiskySignInBlockDisabled {
		t.Error("no high-risk blocking policy means both risk-block flags are violations")
	}

	// End to end: the live snapshot must actually drive the assessor.
	want := map[string]bool{
		"sspm::m365::sharepoint-anonymous-sharing":  false,
		"sspm::m365::weak-mfa-methods-enabled":      false,
		"sspm::m365::user-app-registration-allowed": false,
		"sspm::m365::risky-users-not-blocked":       false,
		"sspm::m365::anyone-link-expiry-too-long":   false,
		"sspm::m365::default-sharing-scope-anyone":  false,
	}
	for _, f := range AssessM365(snap, Options{}) {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
	}
	for rule, fired := range want {
		if !fired {
			t.Errorf("live-fetched snapshot did not produce %s", rule)
		}
	}
}

// A hardened tenant read live must yield ZERO findings — the fetcher must not invent
// posture, and the enum mapping must not mistake a compliant value for a violation.
func TestFetchM365Posture_HardenedTenantIsClean(t *testing.T) {
	srv := fakeGraph(t, map[string]string{
		"/admin/sharepoint/settings": `{
			"sharingCapability":"existingExternalUserSharingOnly",
			"oneDriveSharingCapability":"disabled",
			"sharingDomainRestrictionMode":"allowList",
			"defaultSharingLinkType":"direct",
			"defaultLinkPermission":"view",
			"anonymousLinkExpirationRestrictionDays":30}`,
		"/policies/authenticationMethodsPolicy": `{"authenticationMethodConfigurations":[
			{"id":"Sms","state":"disabled"},{"id":"Voice","state":"disabled"},
			{"id":"Email","state":"disabled"},{"id":"Fido2","state":"enabled"}]}`,
		"/policies/authorizationPolicy": `{"defaultUserRolePermissions":{"allowedToCreateApps":false}}`,
		"/identity/conditionalAccess/policies": `{"value":[
			{"state":"enabled","conditions":{"userRiskLevels":["high"]},"grantControls":{"builtInControls":["block"]}},
			{"state":"enabled","conditions":{"signInRiskLevels":["high"]},"grantControls":{"builtInControls":["block"]}}]}`,
	})
	defer srv.Close()

	snap, err := FetchM365Posture(context.Background(), srv.URL, "hardened", "tok", srv.Client())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	// mailbox auditing is not Graph-readable, so the assessor's default would flag it;
	// the live path leaves it unset. Set it explicitly to isolate what WAS read.
	snap.MailboxAuditingEnabled = BoolPtr(true)
	if f := AssessM365(snap, Options{}); len(f) != 0 {
		t.Errorf("hardened live-read tenant produced %d finding(s), want 0: %s", len(f), ruleIDs(f))
	}
}

// The grounding property that matters most: when Graph refuses an endpoint (missing
// scope, unlicensed feature), the corresponding fields stay ZERO and NO finding is
// invented for them. A partial read may only under-report, never over-report.
func TestFetchM365Posture_PartialReadNeverInventsFindings(t *testing.T) {
	// Only the authorization policy is permitted; everything else 403s.
	srv := fakeGraph(t, map[string]string{
		"/policies/authorizationPolicy": `{"defaultUserRolePermissions":{"allowedToCreateApps":false}}`,
	})
	defer srv.Close()

	snap, err := FetchM365Posture(context.Background(), srv.URL, "partial", "tok", srv.Client())
	if err != nil {
		t.Fatalf("a partial read must still succeed: %v", err)
	}
	if snap.SharePointSharing != "" || snap.OneDriveSharing != "" {
		t.Errorf("unreadable sharing settings must stay empty, got %q/%q", snap.SharePointSharing, snap.OneDriveSharing)
	}
	if snap.WeakMFAMethodsEnabled {
		t.Error("an unreadable auth-methods policy must not assert phishable MFA")
	}
	// Critically: the CA endpoint 403'd, so we must NOT conclude "high risk is unblocked".
	if snap.RiskyUserBlockDisabled || snap.RiskySignInBlockDisabled {
		t.Error("an unreadable Conditional Access list must not assert that high risk is unblocked")
	}
	snap.MailboxAuditingEnabled = BoolPtr(true)
	if f := AssessM365(snap, Options{}); len(f) != 0 {
		t.Errorf("partial read invented %d finding(s): %s", len(f), ruleIDs(f))
	}
}

// Nothing readable at all is a real error, not a silently empty "clean" snapshot —
// otherwise a misconfigured app registration would read as a healthy tenant.
func TestFetchM365Posture_NoReadableEndpointIsAnError(t *testing.T) {
	srv := fakeGraph(t, nil)
	defer srv.Close()
	if _, err := FetchM365Posture(context.Background(), srv.URL, "blind", "tok", srv.Client()); err == nil {
		t.Fatal("want an error when no endpoint could be read, got nil")
	}
	if _, err := FetchM365Posture(context.Background(), srv.URL, "blind", "", srv.Client()); err == nil {
		t.Fatal("want an error on an empty token, got nil")
	}
}

func ruleIDs(f []types.Finding) string {
	var ids []string
	for _, x := range f {
		ids = append(ids, x.RuleID)
	}
	return strings.Join(ids, ", ")
}

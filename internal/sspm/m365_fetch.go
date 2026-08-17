package sspm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchM365Posture builds an M365Tenant collaboration/posture snapshot LIVE from Microsoft
// Graph, reusing the already-onboarded M365 connection's token — the same pattern as
// FetchGitHubOrg, so the SCuBA-derived checks run with no extra credential and no
// hand-posted JSON. This is the fetch half of the CISA SCuBA neutral benchmark
// (internal/bench/scuba.go): the checks existed, but until now a real tenant had to
// supply the snapshot by hand.
//
// HONEST SCOPE — what Graph genuinely exposes, and what it does not. This boundary is
// not a TODO list; it is a property of Microsoft's APIs:
//
//	READABLE via Graph (covered here):
//	  · /admin/sharepoint/settings      → SharePoint + OneDrive sharing level, domain
//	                                      allow-listing, default link scope/permission,
//	                                      anonymous-link expiry
//	  · /policies/authenticationMethodsPolicy → SMS / Voice / Email-OTP enabled (phishable MFA)
//	  · /policies/authorizationPolicy   → any user may register applications
//	  · /identity/conditionalAccess/policies → whether a policy actually BLOCKS high-risk
//	                                      users / high-risk sign-ins
//
//	NOT readable via Graph (stay on the posted-snapshot path):
//	  · Teams meeting policies (anonymous meeting start) — Teams PowerShell (CsTeamsMeetingPolicy)
//	  · Exchange transport posture (external auto-forwarding, mailbox auditing, external
//	    sender tagging) — Exchange Online PowerShell, not Graph
//	  · PIM permanent-vs-eligible privileged assignments — needs Entra ID P2 and the
//	    role-management schedule APIs
//
// Grounded (§10): every read is best-effort and a field Graph will not return for this
// tenant (insufficient scope, unlicensed feature, endpoint unavailable) keeps its ZERO
// value — which the assessor treats as "not supplied" and never as a violation. So a
// partial read can never manufacture a finding; it can only fail to find one. Required
// scopes: SharePointTenantSettings.Read.All, Policy.Read.All. The caller decides whether
// to surface a partial read; err is returned only when NOTHING could be read.
func FetchM365Posture(ctx context.Context, apiBase, tenantName, token string, hc *http.Client) (M365Tenant, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	apiBase = strings.TrimRight(apiBase, "/")
	if apiBase == "" {
		apiBase = "https://graph.microsoft.com"
	}
	if strings.TrimSpace(token) == "" {
		return M365Tenant{}, fmt.Errorf("m365 posture sync: empty token")
	}
	snap := M365Tenant{Name: tenantName}
	var read int

	// --- SharePoint / OneDrive sharing settings ---
	var sp struct {
		SharingCapability            string `json:"sharingCapability"`
		OneDriveSharingCapability    string `json:"oneDriveSharingCapability"`
		SharingDomainRestrictionMode string `json:"sharingDomainRestrictionMode"`
		DefaultSharingLinkType       string `json:"defaultSharingLinkType"`
		DefaultLinkPermission        string `json:"defaultLinkPermission"`
		// 0 means "no restriction" i.e. anonymous links never expire.
		AnonymousLinkExpirationRestrictionDays int  `json:"anonymousLinkExpirationRestrictionDays"`
		IsSharingCapabilityRestricted          bool `json:"isSharingCapabilityRestricted"`
	}
	if err := graphGet(ctx, hc, apiBase+"/v1.0/admin/sharepoint/settings", token, &sp); err == nil {
		read++
		snap.SharePointSharing = sharingLevel(sp.SharingCapability)
		// Graph omits oneDriveSharingCapability on some tenants; SCuBA reads OneDrive as
		// "no more permissive than SharePoint", so fall back to the tenant level rather
		// than inventing a stricter value.
		snap.OneDriveSharing = sharingLevel(sp.OneDriveSharingCapability)
		if snap.OneDriveSharing == "" {
			snap.OneDriveSharing = snap.SharePointSharing
		}
		snap.ExternalDomainAllowlist = strings.EqualFold(sp.SharingDomainRestrictionMode, "allowList")
		if strings.EqualFold(sp.DefaultSharingLinkType, "anonymousAccess") {
			snap.DefaultSharingScope = "anyone"
		}
		if strings.EqualFold(sp.DefaultLinkPermission, "edit") {
			snap.DefaultLinkPermission = "edit"
		}
		// Only meaningful once anonymous links are possible at all: on a tenant that
		// cannot mint them, an unlimited expiry window is not an exposure.
		if snap.SharePointSharing == "anonymous" {
			if sp.AnonymousLinkExpirationRestrictionDays == 0 {
				snap.AnyoneLinksNeverExpire = true
			} else {
				snap.AnyoneLinkExpiryDays = sp.AnonymousLinkExpirationRestrictionDays
			}
		}
	}

	// --- Authentication methods policy: phishable factors still enabled ---
	var amp struct {
		Configurations []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"authenticationMethodConfigurations"`
	}
	if err := graphGet(ctx, hc, apiBase+"/v1.0/policies/authenticationMethodsPolicy", token, &amp); err == nil {
		read++
		for _, c := range amp.Configurations {
			switch strings.ToLower(c.ID) {
			case "sms", "voice", "email":
				if strings.EqualFold(c.State, "enabled") {
					snap.WeakMFAMethodsEnabled = true
				}
			}
		}
	}

	// --- Authorization policy: self-service app registration ---
	var ap struct {
		DefaultUserRolePermissions struct {
			AllowedToCreateApps bool `json:"allowedToCreateApps"`
		} `json:"defaultUserRolePermissions"`
	}
	if err := graphGet(ctx, hc, apiBase+"/v1.0/policies/authorizationPolicy", token, &ap); err == nil {
		read++
		snap.UserAppRegistrationAllowed = ap.DefaultUserRolePermissions.AllowedToCreateApps
	}

	// --- Conditional Access: is high risk actually BLOCKED? ---
	var ca struct {
		Value []struct {
			State      string `json:"state"`
			Conditions struct {
				UserRiskLevels   []string `json:"userRiskLevels"`
				SignInRiskLevels []string `json:"signInRiskLevels"`
			} `json:"conditions"`
			GrantControls struct {
				BuiltInControls []string `json:"builtInControls"`
			} `json:"grantControls"`
		} `json:"value"`
	}
	if err := graphGet(ctx, hc, apiBase+"/v1.0/identity/conditionalAccess/policies", token, &ca); err == nil {
		read++
		var userBlocked, signInBlocked bool
		for _, p := range ca.Value {
			if !strings.EqualFold(p.State, "enabled") || !contains(p.GrantControls.BuiltInControls, "block") {
				continue
			}
			if contains(p.Conditions.UserRiskLevels, "high") {
				userBlocked = true
			}
			if contains(p.Conditions.SignInRiskLevels, "high") {
				signInBlocked = true
			}
		}
		// Absence of a blocking policy IS the SCuBA violation (MS.AAD.2.1v1 / 2.3v1) —
		// but only assert it when the policy list was really read, never on a failed call.
		snap.RiskyUserBlockDisabled = !userBlocked
		snap.RiskySignInBlockDisabled = !signInBlocked
	}

	if read == 0 {
		return M365Tenant{}, fmt.Errorf("m365 posture sync: no Graph endpoint could be read (check Policy.Read.All / SharePointTenantSettings.Read.All)")
	}
	return snap, nil
}

// sharingLevel maps Graph's sharingCapability enum onto the snapshot's vocabulary.
// An unrecognised or absent value returns "" — not supplied, so no check fires.
func sharingLevel(capability string) string {
	switch strings.ToLower(strings.TrimSpace(capability)) {
	case "externaluserandguestsharing":
		return "anonymous" // "Anyone" links — unauthenticated
	case "externalusersharingonly":
		return "external" // any guest, authenticated
	case "existingexternalusersharingonly":
		return "domains" // pre-existing guests only — the SCuBA-acceptable state
	case "disabled":
		return "internal"
	default:
		return ""
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if strings.EqualFold(strings.TrimSpace(x), want) {
			return true
		}
	}
	return false
}

// graphGet is the Graph read helper: bearer auth, JSON decode, bounded body read. A
// non-2xx is an error so the caller leaves the corresponding fields at zero.
func graphGet(ctx context.Context, hc *http.Client, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("graph: GET %s: status %d", endpoint, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// BoolPtr is the constructor for the tri-state posture fields (nil = not supplied).
// Exported because callers outside this package build M365Tenant snapshots.
func BoolPtr(b bool) *bool { return &b }

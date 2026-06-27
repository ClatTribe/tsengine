package sspm

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// GWorkspaceTenant is a grounded snapshot of a Google Workspace tenant's COLLABORATION / DATA-SHARING posture —
// the Drive / Gmail / Calendar / app-access settings that expose corporate data. DISTINCT from the Google
// Workspace IDENTITY posture (MFA/2SV, OAuth grants, stale accounts) the `operate` engine already covers: it
// closes the SSPM gap where we did Google's identity half but not its Drive/Gmail data-sharing half. With M365
// (`m365.go`), these are the two most-common SaaS estates. Sourced from the Google Admin SDK / Drive API (the
// credential-gated half — reuses the onboarded Google token) or a posted snapshot. Snapshot-driven, LLM-free,
// grounded: a hardened tenant yields zero findings. Reuses the package finding/comp helpers.
type GWorkspaceTenant struct {
	Name string `json:"name"`
	// Drive external-sharing level: "public" (Anyone on the internet — anonymous) | "external" (any external
	// user) | "domains" (allowlisted) | "restricted" (off). "public" is the worst.
	DriveSharing             string `json:"drive_sharing"`
	DriveExternalAllowlist   bool   `json:"drive_external_allowlist"`   // external Drive sharing limited to allowlisted domains
	DriveLinkSharingDefault  bool   `json:"drive_link_sharing_default"` // new files default to link-sharing (anyone-with-link)
	LessSecureAppsEnabled    bool   `json:"less_secure_apps_enabled"`   // legacy "less secure app" access (password basic-auth, MFA-bypass)
	ThirdPartyAPIAccess      bool   `json:"third_party_api_access"`     // any third-party OAuth app can access data (no app allowlist / API controls)
	GmailExternalAutoForward bool   `json:"gmail_external_autoforward"` // users may auto-forward mail to external addresses (exfil)
	ExternalCalendarSharing  bool   `json:"external_calendar_sharing"`  // calendar details shared with external/public
}

// AssessGoogleWorkspace runs every grounded collaboration/data-sharing posture check over a Google Workspace
// snapshot. A securely configured tenant returns nil.
func AssessGoogleWorkspace(t GWorkspaceTenant, opts Options) []types.Finding {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	n := 0
	id := func() string { n++; return fmt.Sprintf("sspm-gworkspace-%03d", n) }
	target := "google_workspace:" + t.Name

	var f []types.Finding
	if strings.EqualFold(t.DriveSharing, "public") {
		f = append(f, finding(id(), "sspm::google_workspace::drive-public-sharing", types.SeverityHigh,
			"Drive allows public ('Anyone on the internet') sharing", target+"/drive",
			"Drive sharing is set to 'Anyone on the internet' — anonymous, unauthenticated links to corporate documents. Restrict Drive external sharing to 'Off' or allowlisted domains.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.6"}, PCI: []string{"7.2.1"}, HIPAA: []string{"164.312(a)(1)"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-3"}})))
	}
	if strings.EqualFold(t.DriveSharing, "external") && !t.DriveExternalAllowlist {
		f = append(f, finding(id(), "sspm::google_workspace::drive-external-no-allowlist", types.SeverityMedium,
			"Drive external sharing is not restricted to allowlisted domains", target+"/drive",
			"Drive can be shared with any external user. Restrict external sharing to an allowlist of trusted partner domains so corporate data can't leave to arbitrary accounts.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AC-4"}, GDPR: []string{"Art. 32"}})))
	}
	if t.DriveLinkSharingDefault {
		f = append(f, finding(id(), "sspm::google_workspace::drive-link-sharing-default", types.SeverityMedium,
			"New Drive files default to link-sharing", target+"/drive",
			"New files default to 'anyone with the link' sharing — data is exposed by default rather than by deliberate choice. Set the default access to 'Private to the owner'.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-1"}})))
	}
	if t.LessSecureAppsEnabled {
		f = append(f, finding(id(), "sspm::google_workspace::less-secure-apps-enabled", types.SeverityHigh,
			"'Less secure app' access is enabled", target,
			"Less-secure-app access permits basic-auth sign-in that bypasses 2-step verification — a password-spray / account-takeover vector. Disable less-secure-app access org-wide.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, HIPAA: []string{"164.312(d)"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AC-7"}, NIST80053: []string{"IA-2"}})))
	}
	if t.ThirdPartyAPIAccess {
		f = append(f, finding(id(), "sspm::google_workspace::third-party-app-access-unrestricted", types.SeverityMedium,
			"Third-party app API access is unrestricted", target,
			"Any third-party OAuth app can be granted access to Drive/Gmail data with no app allowlist or API-access controls — a shadow-IT + data-exfil risk. Restrict API access to vetted, allowlisted apps.",
			now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}, NISTCSF: []string{"PR.AC-5"}})))
	}
	if t.GmailExternalAutoForward {
		f = append(f, finding(id(), "sspm::google_workspace::gmail-external-autoforward", types.SeverityMedium,
			"Users may auto-forward mail to external addresses", target+"/gmail",
			"Automatic forwarding to external addresses is allowed — a common data-exfiltration + BEC-persistence technique. Disable external auto-forwarding (allow only admin-approved exceptions).",
			now, comp(types.Compliance{SOC2: []string{"CC6.6"}, HIPAA: []string{"164.312(e)(1)"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.DS-5"}})))
	}
	if t.ExternalCalendarSharing {
		f = append(f, finding(id(), "sspm::google_workspace::external-calendar-sharing", types.SeverityLow,
			"Calendar details are shared externally", target+"/calendar",
			"Calendars publish full event details externally — leaking meeting subjects, attendees, and availability (useful for social-engineering). Limit external calendar sharing to free/busy only.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, GDPR: []string{"Art. 32"}, NISTCSF: []string{"PR.DS-1"}})))
	}
	return f
}

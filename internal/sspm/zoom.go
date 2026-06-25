package sspm

import (
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// ZoomAccount is a grounded snapshot of a Zoom account's security configuration — the account /
// admin settings that carry a real control (sign-in security + meeting/recording hardening).
// Sourced from the Zoom admin API (Account Settings) or an exported snapshot. The third SSPM app
// (ADR 0004, after GitHub + Slack); reuses the package's finding/comp helpers. A securely-configured
// account yields ZERO findings (the testability invariant).
type ZoomAccount struct {
	Name                    string       `json:"name"`
	TwoFactorRequired       bool         `json:"two_factor_required"`       // account 2FA enforcement
	SSOEnforced             bool         `json:"sso_enforced"`              // SAML/SSO required for sign-in
	MeetingPasscodeRequired bool         `json:"meeting_passcode_required"` // every meeting needs a passcode
	WaitingRoomEnabled      bool         `json:"waiting_room_enabled"`      // waiting room on by default
	CloudRecordingEncrypted bool         `json:"cloud_recording_encrypted"` // cloud recordings require passcode / are encrypted
	RecordingAutoDelete     bool         `json:"recording_auto_delete"`     // a recording retention / auto-delete policy is set
	ApprovedAppsOnly        bool         `json:"approved_apps_only"`        // Marketplace app pre-approval required
	Members                 []ZoomMember `json:"members"`
	Apps                    []ZoomApp    `json:"apps"`
}

// ZoomMember is one account user. Role ∈ owner|admin|member.
type ZoomMember struct {
	Email     string `json:"email"`
	Role      string `json:"role"`
	TwoFactor bool   `json:"two_factor"`
}

// ZoomApp is an installed Zoom Marketplace app / integration.
type ZoomApp struct {
	Name       string `json:"name"`
	Verified   bool   `json:"verified"`    // Zoom-Marketplace published / verified
	BroadScope bool   `json:"broad_scope"` // holds broad data scopes (read all recordings/users, admin)
}

// AssessZoom runs every grounded posture check over a Zoom account snapshot.
// A securely-configured account returns nil.
func AssessZoom(acc ZoomAccount, opts Options) []types.Finding {
	if opts.MaxOwners <= 0 {
		opts.MaxOwners = 3
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	n := 0
	id := func() string { n++; return fmt.Sprintf("sspm-zoom-%03d", n) }
	target := "zoom:" + acc.Name

	var f []types.Finding
	f = append(f, zoomCheck2FA(acc, target, now, id)...)
	f = append(f, zoomCheckMember2FA(acc, target, now, id)...)
	f = append(f, zoomCheckSSO(acc, target, now, id)...)
	f = append(f, zoomCheckMeetingPasscode(acc, target, now, id)...)
	f = append(f, zoomCheckWaitingRoom(acc, target, now, id)...)
	f = append(f, zoomCheckRecordingEncryption(acc, target, now, id)...)
	f = append(f, zoomCheckRecordingRetention(acc, target, now, id)...)
	f = append(f, zoomCheckApprovedApps(acc, target, now, id)...)
	f = append(f, zoomCheckApps(acc, target, now, id)...)
	f = append(f, zoomCheckAdminSprawl(acc, opts.MaxOwners, target, now, id)...)
	return f
}

func zoomCheck2FA(acc ZoomAccount, target string, now time.Time, id func() string) []types.Finding {
	if acc.TwoFactorRequired || acc.SSOEnforced { // SSO providers carry MFA upstream
		return nil
	}
	return []types.Finding{finding(id(), "sspm::zoom::2fa-not-enforced", types.SeverityHigh,
		"Zoom account does not require two-factor authentication", target,
		"Account 2FA enforcement is OFF and no SSO is required; a phished user password is account access.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}}))}
}

func zoomCheckMember2FA(acc ZoomAccount, target string, now time.Time, id func() string) []types.Finding {
	if acc.TwoFactorRequired || acc.SSOEnforced {
		return nil
	}
	var out []types.Finding
	for _, m := range acc.Members {
		if m.TwoFactor {
			continue
		}
		sev := types.SeverityMedium
		if m.Role == "owner" || m.Role == "admin" {
			sev = types.SeverityHigh
		}
		out = append(out, finding(id(), "sspm::zoom::member-without-2fa", sev,
			"Zoom user without 2FA: "+m.Email, target+"/"+m.Email,
			"User '"+m.Email+"' (role "+m.Role+") has no second factor enabled.",
			now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}})))
	}
	return out
}

func zoomCheckSSO(acc ZoomAccount, target string, now time.Time, id func() string) []types.Finding {
	if acc.SSOEnforced {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::zoom::sso-not-enforced", types.SeverityMedium,
		"Zoom account does not enforce SSO/SAML sign-in", target,
		"Sign-in is not gated by your identity provider, so offboarding and central MFA/conditional-access policies do not apply.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.7"}, NISTCSF: []string{"PR.AA-01"}}))}
}

func zoomCheckMeetingPasscode(acc ZoomAccount, target string, now time.Time, id func() string) []types.Finding {
	if acc.MeetingPasscodeRequired {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::zoom::meeting-passcode-not-required", types.SeverityMedium,
		"Zoom does not require a passcode on every meeting", target,
		"Meetings without a passcode can be joined by guessing/scanning meeting IDs (Zoom-bombing). Require a passcode account-wide.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"3.3"}, NISTCSF: []string{"PR.AA-05"}}))}
}

func zoomCheckWaitingRoom(acc ZoomAccount, target string, now time.Time, id func() string) []types.Finding {
	if acc.WaitingRoomEnabled {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::zoom::waiting-room-disabled", types.SeverityMedium,
		"Zoom waiting room is not enabled by default", target,
		"Without a waiting room, anyone with the link/ID joins directly with no host admittance — an unauthorized-access path. Enable it account-wide.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AA-05"}}))}
}

func zoomCheckRecordingEncryption(acc ZoomAccount, target string, now time.Time, id func() string) []types.Finding {
	if acc.CloudRecordingEncrypted {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::zoom::cloud-recording-not-protected", types.SeverityMedium,
		"Zoom cloud recordings are not passcode-protected / encrypted", target,
		"Cloud recordings without a passcode (or encryption) can be replayed by anyone with the share link — a data-exposure path for recorded meetings.",
		now, comp(types.Compliance{SOC2: []string{"CC6.1", "CC6.7"}, CISv8: []string{"3.3", "3.11"}, GDPR: []string{"Art. 32"}, CCPA: []string{"1798.150"}}))}
}

func zoomCheckRecordingRetention(acc ZoomAccount, target string, now time.Time, id func() string) []types.Finding {
	if acc.RecordingAutoDelete {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::zoom::no-recording-retention", types.SeverityLow,
		"Zoom has no cloud-recording retention / auto-delete policy", target,
		"Recordings are retained indefinitely; a retention/auto-delete policy limits the data-exposure window (data minimization).",
		now, comp(types.Compliance{SOC2: []string{"CC6.2"}, GDPR: []string{"Art. 5"}, CISv8: []string{"3.4"}}))}
}

func zoomCheckApprovedApps(acc ZoomAccount, target string, now time.Time, id func() string) []types.Finding {
	if acc.ApprovedAppsOnly {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::zoom::app-approval-disabled", types.SeverityMedium,
		"Zoom account lets any user install Marketplace apps (no pre-approval)", target,
		"Without app pre-approval any user can connect a third-party app with data access — an ungoverned data-egress path.",
		now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}, NISTCSF: []string{"PR.AA-05"}}))}
}

func zoomCheckApps(acc ZoomAccount, target string, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, a := range acc.Apps {
		switch {
		case a.BroadScope:
			out = append(out, finding(id(), "sspm::zoom::app-broad-scope", types.SeverityHigh,
				"Installed Zoom app holds broad data scopes: "+a.Name, target+"/apps/"+a.Name,
				"App '"+a.Name+"' can read across recordings/users (or admin); confirm it is needed and trusted — a third-party data-exfil surface.",
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8", "16.11"}, GDPR: []string{"Art. 32"}})))
		case !a.Verified:
			out = append(out, finding(id(), "sspm::zoom::app-unverified", types.SeverityMedium,
				"Installed Zoom app is not Marketplace-verified: "+a.Name, target+"/apps/"+a.Name,
				"App '"+a.Name+"' is not published/verified on the Zoom Marketplace; review its access and provenance.",
				now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"16.11"}})))
		}
	}
	return out
}

func zoomCheckAdminSprawl(acc ZoomAccount, max int, target string, now time.Time, id func() string) []types.Finding {
	admins := 0
	for _, m := range acc.Members {
		if m.Role == "owner" || m.Role == "admin" {
			admins++
		}
	}
	if admins <= max {
		return nil
	}
	return []types.Finding{finding(id(), "sspm::zoom::admin-sprawl", types.SeverityMedium,
		fmt.Sprintf("Zoom account has %d owners/admins (admin sprawl)", admins), target,
		fmt.Sprintf("%d users hold owner/admin (> recommended %d); each is broad account control. Reduce to the minimum.", admins, max),
		now, comp(types.Compliance{SOC2: []string{"CC6.3"}, CISv8: []string{"6.8"}, NISTCSF: []string{"PR.AA-05"}}))}
}

package sspm

import (
	"strings"
	"testing"
)

// Every assessor here is deliberately silent about a setting the snapshot did not report — absent
// config is not insecure config (§10). The consequence is that a snapshot carrying almost nothing
// yields zero findings, exactly like a hardened tenant does. These hold the response to telling
// those two apart.
//
// Found by driving the ingest: POST {"login":"acme"} answered findings_detected:0 with no comment.

func TestUnassessed_BareIdentitySnapshotAssessedNothing(t *testing.T) {
	missing, carried := UnassessedFields(GitHubOrg{Login: "acme"})
	if carried != 0 {
		t.Errorf("a snapshot carrying only a login counted %d assessable fields", carried)
	}
	if len(missing) == 0 {
		t.Fatal("nothing reported missing for a snapshot that carried no settings")
	}
	note := UnassessedNote("github_org", GitHubOrg{Login: "acme"})
	if !strings.Contains(note, "no settings at all") {
		t.Errorf("the note does not say nothing was assessed: %q", note)
	}
	if !strings.Contains(note, "not a result") {
		t.Errorf("the note does not say the zero is meaningless: %q", note)
	}
}

// A nil *bool is "not reported" — that is the whole reason these types use pointers. It must not be
// read as a carried value, or "we were never told about 2FA" becomes "2FA was reported off".
func TestUnassessed_NilPointerIsNotReported(t *testing.T) {
	if _, carried := UnassessedFields(GitHubOrg{Login: "a", TwoFactorRequired: nil}); carried != 0 {
		t.Error("a nil *bool counted as a reported setting")
	}
	off := false
	missing, carried := UnassessedFields(GitHubOrg{Login: "a", TwoFactorRequired: &off})
	if carried != 1 {
		t.Errorf("a *bool explicitly set to false was not counted as reported (carried=%d)", carried)
	}
	for _, m := range missing {
		if m == "two_factor_required" {
			t.Error("a reported setting was listed as missing")
		}
	}
}

// A PARTIAL snapshot gets the softer sentence: some checks ran, so the zero is not meaningless — it
// just does not cover everything.
func TestUnassessed_PartialSnapshotSaysWhichAreMissing(t *testing.T) {
	on := true
	note := UnassessedNote("github_org", GitHubOrg{
		Login: "acme", TwoFactorRequired: &on, DefaultRepoPermission: "read"})
	if strings.Contains(note, "no settings at all") {
		t.Error("a partial snapshot was described as carrying nothing")
	}
	if !strings.Contains(note, "members") || !strings.Contains(note, "apps") {
		t.Errorf("the note does not name what is missing: %q", note)
	}
	if !strings.Contains(note, "not a pass") {
		t.Errorf("the note does not say absent settings are not a pass: %q", note)
	}
}

// A COMPLETE snapshot produces no note. A disclaimer on every response is one nobody reads.
func TestUnassessed_CompleteSnapshotIsSilent(t *testing.T) {
	on := true
	full := GitHubOrg{
		Login: "acme", TwoFactorRequired: &on, DefaultRepoPermission: "read",
		MembersCanCreatePublicRepos: true, SecretScanningEnabled: &on,
		Members:              []OrgMember{{Login: "ada", Role: "admin", TwoFactor: true}},
		OutsideCollaborators: []OrgMember{{Login: "ext"}},
		Apps:                 []OrgApp{{Name: "ci", Verified: true}},
		Webhooks:             []OrgWebhook{{URL: "https://x", SSLVerify: true, Active: true}},
	}
	if note := UnassessedNote("github_org", full); note != "" {
		t.Errorf("a complete snapshot produced a note, which trains people to ignore it: %q", note)
	}
}

// It works for EVERY provider, not just the one it was written against — that is the point of
// reading the struct rather than keeping seven hand-written field lists.
func TestUnassessed_CoversEveryProviderShape(t *testing.T) {
	for _, tc := range []struct {
		provider string
		snap     any
	}{
		{"slack", SlackWorkspace{}},
		{"zoom", ZoomAccount{}},
		{"atlassian", AtlassianOrg{}},
		{"salesforce", SalesforceOrg{}},
		{"m365", M365Tenant{}},
		{"google_workspace", GWorkspaceTenant{}},
	} {
		if note := UnassessedNote(tc.provider, tc.snap); note == "" {
			t.Errorf("%s: an empty snapshot produced no note", tc.provider)
		}
	}
}

// A non-struct must not panic — the handler passes whatever the decoder produced.
func TestUnassessed_NonStructIsHarmless(t *testing.T) {
	if note := UnassessedNote("x", nil); note != "" {
		t.Errorf("nil produced a note: %q", note)
	}
	if _, carried := UnassessedFields("not a struct"); carried != 0 {
		t.Error("a non-struct reported carried fields")
	}
}

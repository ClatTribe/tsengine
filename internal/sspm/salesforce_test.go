package sspm

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func hardenedSalesforce() SalesforceOrg {
	return SalesforceOrg{
		Name:             "acme",
		MFARequired:      true,
		SSOEnforced:      true,
		IPRestrictions:   true,
		ApprovedAppsOnly: true,
		Users: []SalesforceUser{
			{Username: "admin@acme.com", Profile: "System Administrator", MFA: true, ModifyAllData: true},
			{Username: "rep@acme.com", Profile: "Sales User", MFA: true, ModifyAllData: false},
		},
		ConnectedApps: []SalesforceApp{{Name: "DocuSign", Verified: true, BroadScope: false}},
		Communities:   []SalesforceCommunity{{Name: "Partner Portal", GuestAccess: false}},
	}
}

func TestAssessSalesforce_HardenedYieldsZero(t *testing.T) {
	if f := AssessSalesforce(hardenedSalesforce(), Options{}); len(f) != 0 {
		t.Fatalf("a hardened Salesforce org must yield zero findings, got %d: %+v", len(f), f)
	}
}

func TestAssessSalesforce_FlagsMisconfig(t *testing.T) {
	org := SalesforceOrg{
		Name:             "acme",
		MFARequired:      false,
		SSOEnforced:      false,
		IPRestrictions:   false,
		ApprovedAppsOnly: false,
		Users: []SalesforceUser{
			{Username: "admin@acme.com", Profile: "System Administrator", MFA: false, ModifyAllData: true},
			{Username: "rep@acme.com", Profile: "Sales User", MFA: false, ModifyAllData: true}, // non-admin w/ MAD
		},
		ConnectedApps: []SalesforceApp{{Name: "ShadyApp", Verified: false, BroadScope: true}},
		Communities:   []SalesforceCommunity{{Name: "Public Help", GuestAccess: true}},
	}
	f := AssessSalesforce(org, Options{})
	rules := map[string]types.Severity{}
	for _, x := range f {
		rules[x.RuleID] = x.Severity
		if x.Tool != "sspm" || x.VerificationStatus != types.VerificationVerified {
			t.Errorf("finding not grounded-verified: %+v", x)
		}
		if !strings.HasPrefix(x.Endpoint, "salesforce:acme") {
			t.Errorf("endpoint not grounded to the org: %q", x.Endpoint)
		}
	}
	for _, want := range []string{
		"sspm::salesforce::mfa-not-enforced",
		"sspm::salesforce::sso-not-enforced",
		"sspm::salesforce::no-ip-restrictions",
		"sspm::salesforce::community-guest-access",
		"sspm::salesforce::modify-all-data",
		"sspm::salesforce::app-approval-disabled",
		"sspm::salesforce::app-broad-scope",
		"sspm::salesforce::user-without-mfa",
	} {
		if _, ok := rules[want]; !ok {
			t.Errorf("expected finding %q not emitted", want)
		}
	}
	// guest community access is a high-severity data-exposure finding
	if rules["sspm::salesforce::community-guest-access"] != types.SeverityHigh {
		t.Errorf("community-guest-access should be high, got %q", rules["sspm::salesforce::community-guest-access"])
	}
	// modify-all-data on a non-admin is high
	if rules["sspm::salesforce::modify-all-data"] != types.SeverityHigh {
		t.Errorf("modify-all-data should be high, got %q", rules["sspm::salesforce::modify-all-data"])
	}
}

func TestAssessSalesforce_AdminMADNotFlagged(t *testing.T) {
	// Modify-All-Data is legitimate on a System Administrator → only flagged on non-admins.
	org := hardenedSalesforce() // admin holds MAD; otherwise hardened
	if f := AssessSalesforce(org, Options{}); len(f) != 0 {
		t.Errorf("admin holding Modify-All-Data must NOT be flagged, got %+v", f)
	}
}

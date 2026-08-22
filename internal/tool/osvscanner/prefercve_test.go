package osvscanner

import "testing"

// preferCVE decides the rule_id, and the rule_id is the ONLY thing the threat-intel hook reads:
// hooks.cvePattern matches `CVE-\d{4}-\d{3,7}` against it. OSV's primary id for an ecosystem
// advisory is usually a GHSA, so without this the rule_id is "osv-scanner::GHSA-jfh8-c2jp-5v3q" and
// Log4Shell arrives with NO KEV listing, no EPSS, no CVSS, no SSVC, and no CWE for compliance.map to
// key on — silently, because a finding with no threat intel looks exactly like one whose CVE simply
// is not in the corpus.
//
// The line is four lines long and was untested. It is load-bearing enough that "simplify it to
// return id" is a plausible edit nothing would have caught.
func TestPreferCVE_PrefersTheAliasTheHookCanRead(t *testing.T) {
	// The real Log4Shell shape, verified against api.osv.dev: primary id GHSA, CVE in aliases.
	if got := preferCVE("GHSA-jfh8-c2jp-5v3q", []string{"CVE-2021-44228"}); got != "CVE-2021-44228" {
		t.Errorf("a GHSA-primary advisory did not surface its CVE: %q — the finding would carry no "+
			"threat intel at all", got)
	}
}

// A CVE-primary record keeps its own id rather than being rewritten.
func TestPreferCVE_KeepsACVEPrimaryID(t *testing.T) {
	if got := preferCVE("CVE-2021-44228", nil); got != "CVE-2021-44228" {
		t.Errorf("a CVE-primary id was altered: %q", got)
	}
}

// No CVE anywhere: the OSV id is kept. It is a real identifier and dropping it would leave the
// finding unnamed — worse than one the corpus cannot enrich.
func TestPreferCVE_FallsBackToTheOSVID(t *testing.T) {
	if got := preferCVE("GHSA-aaaa-bbbb-cccc", []string{"OSV-2021-1", "PYSEC-2021-1"}); got != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("an advisory with no CVE alias lost its identifier: %q", got)
	}
}

// A non-CVE alias must not be mistaken for one. The hook's pattern would not match it, so returning
// it would silently cost the enrichment the primary id might still have earned.
func TestPreferCVE_IgnoresNonCVEAliases(t *testing.T) {
	got := preferCVE("GHSA-x", []string{"PYSEC-2021-1", "CVE-2020-1234", "OSV-1"})
	if got != "CVE-2020-1234" {
		t.Errorf("expected the CVE among mixed aliases, got %q", got)
	}
}

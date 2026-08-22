package scheduler

import "testing"

// A feed the running platform cannot switch on is a feed nobody has.
//
// SSVC shipped with a parser, a corpus field, an enrichment hook, an L2 digest tag, a finding-page
// badge and a probe-planner gate — every one reachable only from a test, because CorpusRefresher
// built its RefreshOptions without VulnrichmentURL and nothing in cmd/platform could set it. The
// same "built but unreachable" shape this campaign keeps finding, authored by the campaign.
//
// Asserted against the SEAM rather than the network. The obvious version of this test — stub the URL
// and check it was requested — reaches the live internet for the other six feeds, which threatintel's
// own test file documents as having happened twice. It passed in 8.7 seconds and would be flaky in CI.
func TestRefreshOptions_CarriesTheOptInFeeds(t *testing.T) {
	c := &CorpusRefresher{
		ExploitIntelURL: "https://example.test/nuclei.tar.gz",
		VulnrichmentURL: "https://example.test/vulnrichment.tar.gz",
		NVDURL:          "https://example.test/nvd/",
	}
	got := c.refreshOptions("/tmp/corpus")

	if got.VulnrichmentURL != c.VulnrichmentURL {
		t.Errorf("VulnrichmentURL did not reach the refresh (%q) — the feed cannot be switched on "+
			"in the running platform", got.VulnrichmentURL)
	}
	if got.ExploitIntelURL != c.ExploitIntelURL {
		t.Errorf("ExploitIntelURL regressed: %q", got.ExploitIntelURL)
	}
	if got.NVDURL != c.NVDURL {
		t.Errorf("NVDURL did not reach the refresh (%q) — nothing else populates the corpus's CVSS "+
			"field, so without this every entry scores 0", got.NVDURL)
	}
	if got.OutDir != "/tmp/corpus" {
		t.Errorf("OutDir = %q", got.OutDir)
	}
}

// Unconfigured, both opt-in feeds stay off rather than defaulting on: each archive is large, and a
// default would make every deployment fetch them.
func TestRefreshOptions_OptInFeedsAreOffByDefault(t *testing.T) {
	got := (&CorpusRefresher{}).refreshOptions("/tmp/corpus")
	if got.VulnrichmentURL != "" || got.ExploitIntelURL != "" || got.NVDURL != "" {
		t.Errorf("opt-in feeds must stay off unless configured: %+v", got)
	}
}

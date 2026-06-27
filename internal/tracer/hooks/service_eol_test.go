package hooks

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func nmapSvc(product, version string, sev types.Severity) types.Finding {
	return types.Finding{
		ID: "f-1", Tool: "nmap", RuleID: "nmap::open-port::ssh", Severity: sev,
		Title: "ssh on 22/tcp — " + product + " " + version,
		ToolArgs: map[string]string{"product": product, "version": version},
	}
}

func TestServiceEOL_FlagsOutdated(t *testing.T) {
	h := NewServiceEOL()
	// the scanme.nmap.org case: OpenSSH 6.6.1p1 (2014) is below min-safe 8.0
	out, audit, _ := h.Apply(nmapSvc("OpenSSH", "6.6.1p1", types.SeverityInfo))
	if out.Severity != types.SeverityMedium {
		t.Fatalf("outdated OpenSSH should bump to medium, got %s", out.Severity)
	}
	if len(audit) != 1 || audit[0].Rule != "service_eol::outdated-version" || audit[0].FromSeverity != types.SeverityInfo {
		t.Fatalf("expected one promote audit entry, got %+v", audit)
	}
	if !strings.Contains(out.Description, "Outdated service") || !strings.Contains(out.Description, "8.0") {
		t.Errorf("description should explain the outdated version + min-safe, got %q", out.Description)
	}
}

func TestServiceEOL_UpToDateUntouched(t *testing.T) {
	h := NewServiceEOL()
	out, audit, _ := h.Apply(nmapSvc("OpenSSH", "9.6p1", types.SeverityInfo))
	if out.Severity != types.SeverityInfo || len(audit) != 0 || strings.Contains(out.Description, "Outdated") {
		t.Errorf("a current OpenSSH must be left untouched, got sev=%s audit=%d desc=%q", out.Severity, len(audit), out.Description)
	}
}

func TestServiceEOL_ApacheOldBumped(t *testing.T) {
	h := NewServiceEOL()
	out, _, _ := h.Apply(nmapSvc("Apache httpd", "2.4.7", types.SeverityInfo)) // product has two words
	if out.Severity != types.SeverityMedium {
		t.Errorf("Apache httpd 2.4.7 should be flagged outdated, got %s", out.Severity)
	}
}

// The expanded coverage — common data stores / app servers that are high-impact when exposed and outdated —
// flags an old build and leaves a current one alone.
func TestServiceEOL_ExpandedServices(t *testing.T) {
	h := NewServiceEOL()
	old := map[string]string{ // product → an outdated version that MUST be flagged
		"Redis":         "6.2.7",
		"Apache Tomcat": "8.5.50",
		"MongoDB":       "4.4.0",
		"Elasticsearch": "6.8.0",
		"Squid":         "5.7",
		"PHP":           "7.4.3",
		"Samba":         "4.13.0",
		"HAProxy":       "2.4.0",
		"lighttpd":      "1.4.59",
		"CouchDB":       "3.1.0",
		"RabbitMQ":      "3.10.0",
	}
	for product, ver := range old {
		out, audit, _ := h.Apply(nmapSvc(product, ver, types.SeverityInfo))
		if out.Severity != types.SeverityMedium || len(audit) != 1 {
			t.Errorf("%s %s should be flagged outdated (medium), got %s", product, ver, out.Severity)
		}
	}
	// a current build is left alone (no false flag).
	if out, audit, _ := h.Apply(nmapSvc("Redis", "7.2.0", types.SeverityInfo)); out.Severity != types.SeverityInfo || audit != nil {
		t.Errorf("a current Redis must not be flagged, got %s", out.Severity)
	}
}

func TestServiceEOL_IgnoresNonNmapAndUnknown(t *testing.T) {
	h := NewServiceEOL()
	// non-nmap finding
	web := types.Finding{ID: "f-2", Tool: "nuclei", Severity: types.SeverityInfo}
	if out, audit, _ := h.Apply(web); out.Severity != types.SeverityInfo || audit != nil {
		t.Error("non-nmap finding must be untouched")
	}
	// service not in the curated table
	unknown := nmapSvc("WeirdDaemon", "1.0", types.SeverityInfo)
	if out, audit, _ := h.Apply(unknown); out.Severity != types.SeverityInfo || audit != nil {
		t.Error("a service not in the table must be untouched (no guess)")
	}
	// unparseable version → no flag
	opaque := nmapSvc("OpenSSH", "unknown", types.SeverityInfo)
	if out, _, _ := h.Apply(opaque); out.Severity != types.SeverityInfo {
		t.Error("an unparseable version must not be flagged")
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b      string
		less, okv bool
	}{
		{"6.6.1p1", "8.0", true, true},
		{"2.4.7", "2.4.56", true, true},
		{"9.6p1", "8.0", false, true},
		{"2.4.56", "2.4.56", false, true},
		{"1.18.0", "1.24.0", true, true},
		{"abc", "1.0", false, false}, // unparseable
	}
	for _, c := range cases {
		less, ok := versionLess(c.a, c.b)
		if less != c.less || ok != c.okv {
			t.Errorf("versionLess(%q,%q)=(%v,%v), want (%v,%v)", c.a, c.b, less, ok, c.less, c.okv)
		}
	}
}

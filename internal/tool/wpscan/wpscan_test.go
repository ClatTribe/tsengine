package wpscan

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func TestRegistered(t *testing.T) {
	if _, ok := tool.Get("wpscan"); !ok {
		t.Fatal("wpscan not registered via init()")
	}
}

func TestKnownArgs(t *testing.T) {
	if got := New().KnownArgs(); len(got) != 1 || got[0] != "target" {
		t.Errorf("KnownArgs = %v, want [target]", got)
	}
}

func TestRun_MissingTarget(t *testing.T) {
	if _, err := New().Run(nil, tool.Args{}); err == nil {
		t.Error("expected error for missing target")
	}
}

// sample mirrors the high-signal subset of a real `wpscan --format json` run:
// a vulnerable plugin (with CVE), a core vuln (no CVE), an exposed wp-config
// backup, and enumerated users.
const sample = `{
  "version": {
    "number": "5.8",
    "vulnerabilities": [
      { "title": "WordPress 5.8 XSS in block editor", "references": { "cve": [] } }
    ]
  },
  "plugins": {
    "contact-form-7": {
      "slug": "contact-form-7",
      "version": { "number": "5.3.1" },
      "vulnerabilities": [
        { "title": "Contact Form 7 < 5.3.2 - Unrestricted File Upload",
          "fixed_in": "5.3.2",
          "references": { "cve": ["2020-35489"] } }
      ]
    }
  },
  "interesting_findings": [
    { "url": "https://blog.example/wp-config.php.bak", "type": "config_backup",
      "to_s": "Config backup found: https://blog.example/wp-config.php.bak" },
    { "url": "https://blog.example/xmlrpc.php", "type": "xmlrpc",
      "to_s": "XML-RPC seems to be enabled" }
  ],
  "users": { "admin": {}, "editor": {} }
}`

func TestParse_GroundedFindings(t *testing.T) {
	out := parse([]byte(sample), "https://blog.example")
	if len(out) == 0 {
		t.Fatal("no findings parsed")
	}

	var sawPluginCVE, sawCoreVuln, sawConfigBak, sawXMLRPCInfo, sawUserEnum bool
	for _, f := range out {
		switch {
		case f.RuleID == "wpscan::CVE-2020-35489":
			sawPluginCVE = true
			if f.Severity != "high" {
				t.Errorf("plugin CVE finding severity = %q, want high", f.Severity)
			}
			if !strings.Contains(f.Title, "Contact Form 7") {
				t.Errorf("plugin CVE title lost component: %q", f.Title)
			}
		case f.RuleID == "wpscan::vuln" && strings.Contains(f.Title, "WordPress core"):
			sawCoreVuln = true
		case f.RuleID == "wpscan::interesting::config_backup":
			sawConfigBak = true
			if f.Severity != "high" {
				t.Errorf("config-backup exposure should be high, got %q", f.Severity)
			}
		case f.RuleID == "wpscan::interesting::xmlrpc":
			sawXMLRPCInfo = true
			if f.Severity != "info" {
				t.Errorf("xmlrpc presence should be info, got %q", f.Severity)
			}
		case f.RuleID == "wpscan::user-enumeration":
			sawUserEnum = true
		}
	}
	if !sawPluginCVE {
		t.Error("missing vulnerable-plugin CVE finding (the #1 WordPress risk) — CVE must ride in the rule_id for threat_intel enrichment")
	}
	if !sawCoreVuln {
		t.Error("missing WordPress core vuln finding")
	}
	if !sawConfigBak {
		t.Error("missing exposed wp-config backup finding")
	}
	if !sawXMLRPCInfo {
		t.Error("missing informational xmlrpc finding")
	}
	if !sawUserEnum {
		t.Error("missing user-enumeration finding")
	}
}

func TestParse_Garbage(t *testing.T) {
	if out := parse([]byte("not json"), "https://x"); out != nil {
		t.Errorf("garbage input should yield nil findings, got %d", len(out))
	}
}

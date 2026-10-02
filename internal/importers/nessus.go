package importers

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/fixunit"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// --- Tenable Nessus (.nessus v2 XML) ---
//
// Nessus (and Tenable.io / Tenable.sc, which export the same .nessus format) is the network scanner a
// mid-market security team most often already pays for. A CTEM programme aggregates what the buyer
// already runs; it does not ask them to throw it away. So the export is accepted as-is and every
// finding in it goes through the same enrichment, ranking and fix plan as one we found ourselves.
//
// # Two decisions that shape the output
//
// ONE FINDING PER CVE, ONE FIX STEP PER PLUGIN. A Nessus plugin is Tenable's remediation unit — one
// missing patch — and often names dozens of CVEs. Collapsing them into one finding would let only one
// CVE be looked up against KEV/EPSS (the enrichment reads the CVE from the rule id), so a KEV-listed,
// ransomware-linked CVE could sit unseen inside a plugin whose first CVE is obscure. Splitting them
// fixes that, and the plugin rides as the scanner-declared fix unit (fixunit.ToolArgFixUnit), so the
// fix plan still shows ONE step for the one patch rather than forty.
//
// INFORMATIONAL ITEMS ARE COUNTED, NOT IMPORTED. Severity-0 plugins are inventory — "port open",
// "OS identified", "traceroute" — and a typical scan carries hundreds. Importing them would bury the
// real findings in a backlog the customer is trying to shrink. They are not hidden either: the count
// rides back to the caller (ImportStats.SkippedInformational) so "we imported 40" never reads as "the
// scan only found 40 things".

type nessusDoc struct {
	XMLName xml.Name       `xml:"NessusClientData_v2"`
	Reports []nessusReport `xml:"Report"`
}

type nessusReport struct {
	Name  string       `xml:"name,attr"`
	Hosts []nessusHost `xml:"ReportHost"`
}

type nessusHost struct {
	Name  string       `xml:"name,attr"`
	Tags  []nessusTag  `xml:"HostProperties>tag"`
	Items []nessusItem `xml:"ReportItem"`
}

type nessusTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusItem struct {
	Port         string   `xml:"port,attr"`
	Protocol     string   `xml:"protocol,attr"`
	SvcName      string   `xml:"svc_name,attr"`
	Severity     string   `xml:"severity,attr"` // 0 info · 1 low · 2 medium · 3 high · 4 critical
	PluginID     string   `xml:"pluginID,attr"`
	PluginName   string   `xml:"pluginName,attr"`
	PluginFamily string   `xml:"pluginFamily,attr"`
	Description  string   `xml:"description"`
	Solution     string   `xml:"solution"`
	Synopsis     string   `xml:"synopsis"`
	CVEs         []string `xml:"cve"`
	CWEs         []string `xml:"cwe"`
	CVSS3        string   `xml:"cvss3_base_score"`
	ExploitAvail string   `xml:"exploit_available"`
	PluginOutput string   `xml:"plugin_output"`
}

// ImportStats is what a parser did NOT turn into findings, so the caller can say so.
type ImportStats struct {
	SkippedInformational int `json:"skipped_informational,omitempty"`
}

var nessusCVE = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// FromNessus parses a .nessus v2 export into a types.Scan.
func FromNessus(data []byte, target string, now time.Time) (types.Scan, ImportStats, error) {
	var doc nessusDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return types.Scan{}, ImportStats{}, fmt.Errorf("nessus: %w", err)
	}
	if len(doc.Reports) == 0 {
		return types.Scan{}, ImportStats{}, fmt.Errorf("nessus: no <Report> in the file")
	}
	if target == "" {
		target = firstNonEmpty(doc.Reports[0].Name, "nessus-scan")
	}
	scan := newScan("ip_address", target, now)
	scan.AnchorsFired = []string{"nessus"}
	var stats ImportStats

	n := 0
	for _, rep := range doc.Reports {
		for _, h := range rep.Hosts {
			host := nessusHostName(h)
			for _, it := range h.Items {
				sev := nessusSeverity(it.Severity)
				if sev == types.SeverityInfo {
					stats.SkippedInformational++
					continue
				}
				endpoint := host
				if p := strings.TrimSpace(it.Port); p != "" && p != "0" {
					endpoint = host + ":" + p
				}
				base := types.Finding{
					Tool:     "nessus",
					Severity: sev,
					Title:    firstNonEmpty(it.PluginName, "Nessus plugin "+it.PluginID),
					// The plugin's own words, its fix, and what it actually saw on this host — the
					// plugin output is the evidence, and a finding without it is a claim.
					Description:     nessusDesc(it),
					Endpoint:        endpoint,
					CWE:             nessusCWEs(it.CWEs),
					DiscoveredAt:    now,
					DiscoveryMethod: &types.DiscoveryMethod{Primary: "imported:nessus"},
					ToolArgs: map[string]string{
						"plugin_id":      it.PluginID,
						"plugin_family":  it.PluginFamily,
						ToolArgFixUnit:   "nessus-plugin:" + it.PluginID,
						"protocol":       it.Protocol,
						"service":        it.SvcName,
						"cvss3_base":     strings.TrimSpace(it.CVSS3),
						"exploit_listed": strings.TrimSpace(it.ExploitAvail),
					},
				}
				cves := nessusCVEs(it.CVEs)
				if len(cves) == 0 {
					n++
					f := base
					f.ID = fmt.Sprintf("imp-nessus-%05d", n)
					f.RuleID = "nessus::" + it.PluginID
					scan.FindingsRaw = append(scan.FindingsRaw, f)
					continue
				}
				for _, cve := range cves {
					n++
					f := base
					f.ToolArgs = cloneArgs(base.ToolArgs)
					f.ID = fmt.Sprintf("imp-nessus-%05d", n)
					// The CVE in the rule id is what threat-intel enrichment reads.
					f.RuleID = "nessus::" + it.PluginID + "::" + cve
					scan.FindingsRaw = append(scan.FindingsRaw, f)
				}
			}
		}
	}
	scan.FindingsEnriched = scan.FindingsRaw
	return scan, stats, nil
}

// ToolArgFixUnit is fixunit's scanner-declared remediation unit (one patch for every CVE a Nessus plugin
// names); re-exported so the importers name it in one place.
const ToolArgFixUnit = fixunit.ToolArgFixUnit

// nessusHostName prefers the name a person recognises: the FQDN, then the IP, then the report's label.
func nessusHostName(h nessusHost) string {
	var fqdn, ip string
	for _, t := range h.Tags {
		switch t.Name {
		case "host-fqdn":
			fqdn = strings.TrimSpace(t.Value)
		case "host-ip":
			ip = strings.TrimSpace(t.Value)
		}
	}
	return firstNonEmpty(fqdn, ip, strings.TrimSpace(h.Name), "unknown-host")
}

func nessusSeverity(s string) types.Severity {
	switch strings.TrimSpace(s) {
	case "4":
		return types.SeverityCritical
	case "3":
		return types.SeverityHigh
	case "2":
		return types.SeverityMedium
	case "1":
		return types.SeverityLow
	}
	return types.SeverityInfo
}

func nessusDesc(it nessusItem) string {
	var parts []string
	for _, p := range []struct{ label, v string }{
		{"", it.Synopsis},
		{"", it.Description},
		{"Solution: ", it.Solution},
		{"Observed on this host:\n", it.PluginOutput},
	} {
		if v := strings.TrimSpace(p.v); v != "" {
			parts = append(parts, p.label+v)
		}
	}
	if len(parts) == 0 {
		return "Imported from Nessus with no description."
	}
	return strings.Join(parts, "\n\n")
}

// nessusCVEs keeps only well-formed CVE ids, deduplicated and ordered, so a malformed entry cannot
// become a rule id the enrichment silently fails to match.
func nessusCVEs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if nessusCVE.MatchString(c) && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

func nessusCWEs(in []string) []string {
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CWE-"))
		if c != "" {
			out = append(out, "CWE-"+c)
		}
	}
	return out
}

func cloneArgs(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

package importers

import (
	"encoding/xml"
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// --- Burp Suite (Professional / Enterprise) issues XML ---
//
// Burp is the web-application scanner most security teams already own. Its "Report issues → XML"
// export is accepted as-is, so a team's existing Burp results join the same issues list, ranking and
// fix plan as everything else.
//
// # Burp's confidence is kept, not flattened
//
// Every Burp issue carries a CONFIDENCE (Certain · Firm · Tentative) beside its severity. A Tentative
// issue is Burp saying "this might be real". Importing it as an equal of a Certain one would turn the
// scanner's own doubt into our assertion — so confidence rides on the finding (ToolArgs["confidence"])
// and a Tentative issue says so in its description, in Burp's word, where the reader will see it.
// Nothing here marks an imported issue verified: Burp observed a symptom, and proof is what our own
// exploitation does.

type burpDoc struct {
	XMLName xml.Name    `xml:"issues"`
	Version string      `xml:"burpVersion,attr"`
	Issues  []burpIssue `xml:"issue"`
}

type burpIssue struct {
	Type            string `xml:"type"` // Burp's numeric issue type — stable across scans
	Name            string `xml:"name"`
	Host            string `xml:"host"`
	Path            string `xml:"path"`
	Location        string `xml:"location"`
	Severity        string `xml:"severity"`   // High | Medium | Low | Information
	Confidence      string `xml:"confidence"` // Certain | Firm | Tentative
	IssueBackground string `xml:"issueBackground"`
	Remediation     string `xml:"remediationBackground"`
	IssueDetail     string `xml:"issueDetail"`
	RemediationDet  string `xml:"remediationDetail"`
	Classifications string `xml:"vulnerabilityClassifications"`
}

var (
	burpCWE  = regexp.MustCompile(`CWE-(\d+)`)
	htmlTags = regexp.MustCompile(`<[^>]+>`)
)

// FromBurp parses a Burp issues XML export into a types.Scan.
func FromBurp(data []byte, target string, now time.Time) (types.Scan, ImportStats, error) {
	var doc burpDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return types.Scan{}, ImportStats{}, fmt.Errorf("burp: %w", err)
	}
	var stats ImportStats
	if target == "" && len(doc.Issues) > 0 {
		target = strings.TrimSpace(doc.Issues[0].Host)
	}
	if target == "" {
		target = "burp-scan"
	}
	scan := newScan("web_application", target, now)
	scan.AnchorsFired = []string{"burp"}

	n := 0
	for _, is := range doc.Issues {
		sev := normSeverity(is.Severity)
		if strings.EqualFold(strings.TrimSpace(is.Severity), "information") {
			sev = types.SeverityInfo
		}
		if sev == types.SeverityInfo {
			// Burp's informational issues (an email address disclosed, a cacheable response) are the
			// same inventory noise as Nessus's severity 0 — counted, not imported.
			stats.SkippedInformational++
			continue
		}
		n++
		conf := strings.TrimSpace(is.Confidence)
		scan.FindingsRaw = append(scan.FindingsRaw, types.Finding{
			ID:              fmt.Sprintf("imp-burp-%05d", n),
			RuleID:          "burp::" + firstNonEmpty(strings.TrimSpace(is.Type), short(is.Name)),
			Tool:            "burp",
			Severity:        sev,
			Title:           firstNonEmpty(strings.TrimSpace(is.Name), "Burp issue"),
			Description:     burpDesc(is, conf),
			Endpoint:        burpEndpoint(is),
			CWE:             burpCWEs(is.Classifications),
			DiscoveredAt:    now,
			DiscoveryMethod: &types.DiscoveryMethod{Primary: "imported:burp"},
			ToolArgs:        map[string]string{"confidence": conf, "burp_type": strings.TrimSpace(is.Type)},
		})
	}
	scan.FindingsEnriched = scan.FindingsRaw
	return scan, stats, nil
}

func burpEndpoint(is burpIssue) string {
	host := strings.TrimRight(strings.TrimSpace(is.Host), "/")
	path := strings.TrimSpace(is.Path)
	if host == "" {
		return firstNonEmpty(path, "web-application")
	}
	return host + path
}

// burpDesc renders Burp's HTML fields as text: they are the scanner's own explanation and fix, and the
// issue detail is what it observed at this location.
func burpDesc(is burpIssue, conf string) string {
	var parts []string
	if strings.EqualFold(conf, "tentative") {
		parts = append(parts, "Burp's confidence in this issue is Tentative — the scanner itself is not sure it is real.")
	}
	for _, p := range []struct{ label, v string }{
		{"Observed: ", is.IssueDetail},
		{"", is.IssueBackground},
		{"Remediation: ", firstNonEmpty(is.RemediationDet, is.Remediation)},
	} {
		if v := burpText(p.v); v != "" {
			parts = append(parts, p.label+v)
		}
	}
	if len(parts) == 0 {
		return "Imported from Burp with no description."
	}
	return strings.Join(parts, "\n\n")
}

func burpText(s string) string {
	s = htmlTags.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

func burpCWEs(classifications string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range burpCWE.FindAllStringSubmatch(classifications, -1) {
		c := "CWE-" + m[1]
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

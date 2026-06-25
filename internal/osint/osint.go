// Package osint turns an OPEN-SOURCE-INTELLIGENCE snapshot of an organization's external footprint
// (the attacker's-eye view) into grounded findings that flow through the same one-platform graph as
// every other signal — unified issues, attack-path correlation, compliance posture, and HITL.
//
// It is the §13 "wrap OSS, don't build detectors" pattern applied to OSINT: a deterministic, LLM-free
// core that NORMALIZES what the leading OSINT tools observe — passive recon (theHarvester / SpiderFoot /
// subfinder / amass / crt.sh), breach & credential exposure (HaveIBeenPwned-class feeds), public secret
// leaks (trufflehog / gitleaks over public repos & pastes), typosquat / phishing domains (dnstwist), and
// horizon-scanning advisories (taranis-ai) — into the engine's Finding shape. The tool that produced
// each signal stays the source of truth; this package only classifies + maps to compliance (grounding
// §10). The live collectors are the credential-gated half (most OSINT sources need a key); the posted-
// snapshot path here works today with no external creds, exactly like the SaaS-posture ingest.
package osint

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Snapshot is the normalized OSINT observation an OSINT collector posts for an org. Every slice is the
// verbatim, source-cited output of an OSINT tool/feed — never a guess.
type Snapshot struct {
	Org              string             `json:"org"`
	Domains          []string           `json:"domains"`
	ExposedHosts     []ExposedHost      `json:"exposed_hosts"`     // passive recon: an externally-reachable host/service
	BreachedAccounts []BreachedAccount  `json:"breached_accounts"` // org emails appearing in a known breach
	LeakedSecrets    []LeakedSecret     `json:"leaked_secrets"`    // a credential/secret leaked in a public repo/paste
	Typosquats       []TyposquatDomain  `json:"typosquats"`        // a registered look-alike / phishing domain
	Exposures        []DataExposure     `json:"exposures"`         // org data found exposed on a public/paste/dark site
	Advisories       []Advisory         `json:"advisories"`        // a security advisory relevant to the org's stack/sector
}

type ExposedHost struct {
	Host     string   `json:"host"`               // e.g. legacy.acme.com
	IP       string   `json:"ip,omitempty"`
	Ports    []int    `json:"ports,omitempty"`    // open ports observed passively (Shodan/Censys-style)
	Services []string `json:"services,omitempty"` // e.g. ["http","rdp","mysql"]
	Source   string   `json:"source"`             // the tool/feed that surfaced it (theharvester/crtsh/shodan/…)
	InScope  bool     `json:"in_scope,omitempty"` // already a known monitored asset?
}

type BreachedAccount struct {
	Email   string `json:"email"`
	Breach  string `json:"breach"`            // breach name (e.g. "LinkedIn 2021")
	Date    string `json:"date,omitempty"`    // breach date
	Classes string `json:"classes,omitempty"` // what leaked (e.g. "passwords, emails")
	Source  string `json:"source"`            // hibp / dehashed / …
}

type LeakedSecret struct {
	Kind     string `json:"kind"`              // e.g. "AWS access key", "private key", "Slack token"
	Location string `json:"location"`          // the public URL (repo/paste) it was found at
	Source   string `json:"source"`            // trufflehog / gitleaks / github-search
	Verified bool   `json:"verified,omitempty"`// did the collector validate the secret is live?
}

type TyposquatDomain struct {
	Domain     string `json:"domain"`           // the look-alike domain
	Target     string `json:"target"`           // the brand domain it imitates
	Registered bool   `json:"registered"`       // is it actually registered?
	HasMX      bool   `json:"has_mx,omitempty"` // can it receive mail (phishing-capable)?
	Source     string `json:"source"`           // dnstwist / …
}

type DataExposure struct {
	What     string `json:"what"`     // e.g. "customer email list", "internal doc"
	Location string `json:"location"` // where it was found
	Source   string `json:"source"`
}

type Advisory struct {
	Title     string `json:"title"`
	Component string `json:"component,omitempty"` // the product/tech it concerns (matches the org's stack)
	Severity  string `json:"severity,omitempty"`  // critical|high|medium|low
	URL       string `json:"url,omitempty"`
	Source    string `json:"source"` // taranis-ai / nvd / vendor-advisory
}

// Options tunes the assessment; zero value is sensible defaults.
type Options struct {
	Now func() time.Time
	// NewID, if set, names findings; else a deterministic per-snapshot id is used.
	NewID func() string
}

// Assess turns the OSINT snapshot into grounded findings. Deterministic + LLM-free: a clean external
// footprint (no breaches, no leaks, only in-scope hosts) yields zero findings. Every finding cites the
// OSINT source that observed it (§10). Findings carry inline compliance so they fold into the posture.
func Assess(s Snapshot, opts Options) []types.Finding {
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now()
	}
	n := 0
	id := func() string {
		n++
		if opts.NewID != nil {
			return opts.NewID()
		}
		return fmt.Sprintf("osint-%s-%d", strings.ToLower(strings.TrimSpace(s.Org)), n)
	}

	var out []types.Finding
	out = append(out, assessBreaches(s, now, id)...)
	out = append(out, assessLeaks(s, now, id)...)
	out = append(out, assessExposedHosts(s, now, id)...)
	out = append(out, assessTyposquats(s, now, id)...)
	out = append(out, assessExposures(s, now, id)...)
	out = append(out, assessAdvisories(s, now, id)...)

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// Breached credentials — a known-breach hit for an org email. Verified (the breach record IS the proof).
// Cross-feeds identity: a breached email that also has an MFA gap is a confirmed account-takeover path.
func assessBreaches(s Snapshot, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, b := range s.BreachedAccounts {
		desc := fmt.Sprintf("%s appears in the %s breach", b.Email, nz(b.Breach, "a known"))
		if b.Classes != "" {
			desc += " (leaked: " + b.Classes + ")"
		}
		desc += ". Force a password reset + confirm MFA; the credential may be reused for account takeover."
		out = append(out, finding(id(), "osint::breached-credential", types.SeverityHigh,
			fmt.Sprintf("Breached credential for %s", b.Email), b.Email, desc, now,
			[]string{"CWE-359"}, []string{"T1589"}, src(b.Source),
			types.Compliance{
				SOC2: []string{"CC6.1", "CC7.3"}, PCI: []string{"8.3.1"}, HIPAA: []string{"164.308(a)(6)"},
				GDPR: []string{"Art. 33", "Art. 34"}, CISv8: []string{"5.2", "6.3"}, NISTCSF: []string{"PR.AC-01"},
			}))
	}
	return out
}

// Public secret leaks — a live/exposed secret in a public repo or paste. Critical when validated.
func assessLeaks(s Snapshot, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, l := range s.LeakedSecrets {
		sev := types.SeverityHigh
		if l.Verified {
			sev = types.SeverityCritical
		}
		out = append(out, finding(id(), "osint::leaked-secret", sev,
			fmt.Sprintf("%s leaked publicly%s", l.Kind, verifiedTag(l.Verified)), l.Location,
			fmt.Sprintf("A %s was found exposed at %s (%s). Rotate it immediately and audit for misuse.", l.Kind, l.Location, l.Source),
			now, []string{"CWE-798"}, []string{"T1552"}, src(l.Source),
			types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"3.5.1", "6.3.1"}, CISv8: []string{"16.11"}, NISTCSF: []string{"PR.DS-01"}}))
	}
	return out
}

// Exposed hosts — externally-reachable hosts/services discovered by passive recon. Only the ones NOT
// already in the monitored inventory are findings (shadow / forgotten external surface). Higher severity
// for risky exposed services (rdp/db/smb). These are child-asset pivot candidates (discover → scan).
func assessExposedHosts(s Snapshot, now time.Time, id func() string) []types.Finding {
	risky := map[string]bool{"rdp": true, "mysql": true, "postgres": true, "mongodb": true, "redis": true, "smb": true, "vnc": true, "ftp": true, "telnet": true, "elasticsearch": true}
	var out []types.Finding
	for _, h := range s.ExposedHosts {
		if h.InScope {
			continue // already monitored — not a shadow-exposure finding
		}
		sev := types.SeverityMedium
		hot := ""
		for _, svc := range h.Services {
			if risky[strings.ToLower(svc)] {
				sev = types.SeverityHigh
				hot = svc
			}
		}
		desc := fmt.Sprintf("%s is reachable from the internet but isn't a monitored asset (discovered via %s).", h.Host, h.Source)
		if hot != "" {
			desc += fmt.Sprintf(" It exposes a high-risk service (%s) directly.", hot)
		}
		desc += " Add it to monitoring or take it offline."
		out = append(out, finding(id(), "osint::exposed-host", sev,
			fmt.Sprintf("Unmonitored internet-exposed host: %s", h.Host), h.Host, desc, now,
			nil, []string{"T1590", "T1595"}, src(h.Source),
			types.Compliance{SOC2: []string{"CC6.6", "CC7.1"}, PCI: []string{"11.2.1"}, CISv8: []string{"1.1", "12.4"}, NISTCSF: []string{"ID.AM-01", "DE.CM-08"}}))
	}
	return out
}

// Typosquat / phishing domains — registered look-alikes of the org's brand. Mail-capable ones are
// worse (phishing-ready). Maps to anti-phishing / awareness controls.
func assessTyposquats(s Snapshot, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, t := range s.Typosquats {
		if !t.Registered {
			continue // an unregistered permutation isn't a live threat
		}
		sev := types.SeverityLow
		extra := ""
		if t.HasMX {
			sev = types.SeverityMedium
			extra = " It can receive email, so it's phishing-ready."
		}
		out = append(out, finding(id(), "osint::typosquat-domain", sev,
			fmt.Sprintf("Look-alike domain registered: %s", t.Domain), t.Domain,
			fmt.Sprintf("%s imitates %s and is registered (%s).%s Consider a takedown + a user-awareness note.", t.Domain, nz(t.Target, "your brand"), t.Source, extra),
			now, []string{"CWE-1021"}, []string{"T1583.001"}, src(t.Source),
			types.Compliance{SOC2: []string{"CC6.1"}, NISTCSF: []string{"PR.AT-01", "DE.CM-08"}, ISO27001: []string{"A.5.7"}}))
	}
	return out
}

// Public data exposure — org data found exposed on a public/paste/dark site. A privacy + breach concern.
func assessExposures(s Snapshot, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, e := range s.Exposures {
		out = append(out, finding(id(), "osint::data-exposure", types.SeverityHigh,
			fmt.Sprintf("Org data exposed publicly: %s", e.What), e.Location,
			fmt.Sprintf("'%s' was found exposed at %s (%s). Confirm scope, request takedown, and assess breach-notification duties.", e.What, e.Location, e.Source),
			now, []string{"CWE-200"}, []string{"T1593"}, src(e.Source),
			types.Compliance{SOC2: []string{"CC6.1", "CC6.7"}, GDPR: []string{"Art. 32", "Art. 33"}, CCPA: []string{"§1798.150"}, HIPAA: []string{"164.308(a)(6)"}}))
	}
	return out
}

// Advisories — horizon-scanning (taranis-ai-style) news/advisories relevant to the org's stack. Lower-
// confidence (awareness signal, not a confirmed exposure), so pattern_match, not verified.
func assessAdvisories(s Snapshot, now time.Time, id func() string) []types.Finding {
	var out []types.Finding
	for _, a := range s.Advisories {
		sev := mapSeverity(a.Severity)
		ep := a.Component
		if ep == "" {
			ep = "advisory"
		}
		f := finding(id(), "osint::advisory", sev,
			"Relevant advisory: "+a.Title, ep,
			fmt.Sprintf("A %s-severity advisory affecting %s was published (%s). Review whether your deployment is affected.", nz(a.Severity, "n/a"), nz(a.Component, "a component you use"), nz(a.URL, a.Source)),
			now, nil, []string{"T1592"}, src(a.Source),
			types.Compliance{SOC2: []string{"CC7.1"}, CISv8: []string{"7.1"}, NISTCSF: []string{"ID.RA-02", "DE.CM-08"}})
		// awareness signal, not a proven exposure — be honest about confidence (§10)
		f.VerificationStatus = types.VerificationPatternMatch
		out = append(out, f)
	}
	return out
}

// --- helpers (mirror internal/sspm) ---

func finding(fid, rule string, sev types.Severity, title, endpoint, desc string, now time.Time, cwe, mitre []string, evidence string, c types.Compliance) types.Finding {
	return types.Finding{
		ID: fid, RuleID: rule, Tool: "osint", Severity: sev,
		Title: title, Endpoint: endpoint, Description: desc,
		CWE: cwe, MITRETechniques: mitre,
		Compliance: &c, DiscoveredAt: now,
		// the OSINT observation IS the evidence; breaches/leaks/exposures are facts, so verified.
		VerificationStatus: types.VerificationVerified,
		RawOutput:          []byte(evidence),
	}
}

func src(s string) string {
	if s == "" {
		s = "osint"
	}
	return `{"osint_source":"` + s + `"}`
}

func nz(s, dflt string) string {
	if strings.TrimSpace(s) == "" {
		return dflt
	}
	return s
}

func verifiedTag(v bool) string {
	if v {
		return " (validated live)"
	}
	return ""
}

func mapSeverity(s string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

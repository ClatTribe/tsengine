// Package ctoreadiness scores an engineering org against the security practices expected at its
// funding stage, and says honestly which of them we can actually answer.
//
// This is a DIFFERENT axis from internal/grc. GRC answers "which SOC 2 control does this finding
// affect" — an auditor's question, framed in controls. This answers "what should a company at my
// stage have in place, and which of those am I missing" — a CTO's question, framed in practices and
// staged so a seed company is not measured against a Series C bar.
//
// # The load-bearing idea: four kinds of evidence, and they are not interchangeable
//
// The temptation with any checklist is to render every row green or red. That would be a lie in both
// directions here, because the rows are not the same kind of claim:
//
//   - OBSERVED — a detector answers it. "Are dependencies scanned for CVEs" is answered by actually
//     scanning them. Only these can legitimately read as pass or fail.
//   - CAPABILITY — the product itself is the answer, and the question is whether it is switched on.
//     "Track remediation SLAs and verify every fix" is not something we look for in a customer's
//     estate; it is something this platform does, when configured.
//   - ATTESTED — no scan can see it. Whether production access is gated behind just-in-time elevation
//     lives in a process and another vendor's tool. A human tells us, and we record who and when.
//   - UNBUILT — we do not cover it. Saying so costs a green tick and buys the only thing that makes
//     the other 29 rows worth reading.
//
// A row whose evidence is ATTESTED must never be inferred from findings, and a row that is UNBUILT
// must never be quietly filed as "manual" — that is how a checklist starts flattering its author.
// Both are asserted by tests.
//
// # Grounding (§10)
//
// An observed row reads PASS only when the detector really ran against a connected asset and found
// nothing. With nothing connected it reads NOT CHECKED, never PASS: "we looked and it was clean" and
// "we never looked" are different claims, and on a security checklist the difference is the whole
// point. This is the same discipline the engine applies to findings, applied one level up.
package ctoreadiness

import (
	"sort"
	"strings"
)

// Tier is the funding stage a practice is expected by. The tiers are cumulative: a Series B company
// is measured against seed + series_a + series_b.
type Tier string

const (
	TierSeed    Tier = "seed"
	TierSeriesA Tier = "series_a"
	TierSeriesB Tier = "series_b"
	TierSeriesC Tier = "series_c"
)

// tierOrder ranks tiers for the cumulative filter.
var tierOrder = map[Tier]int{TierSeed: 0, TierSeriesA: 1, TierSeriesB: 2, TierSeriesC: 3}

// Includes reports whether a company at stage `at` is expected to have a practice due at `due`.
func (at Tier) Includes(due Tier) bool { return tierOrder[due] <= tierOrder[at] }

// Valid reports whether t is a stage we recognise.
func (t Tier) Valid() bool { _, ok := tierOrder[t]; return ok }

// Evidence is HOW an item can be answered. See the package comment — these are not interchangeable.
type Evidence string

const (
	EvidenceObserved   Evidence = "observed"
	EvidenceCapability Evidence = "capability"
	EvidenceAttested   Evidence = "attested"
	EvidenceUnbuilt    Evidence = "unbuilt"
)

// Status is the resolved answer for one item for one tenant.
type Status string

const (
	StatusPass       Status = "pass"        // observed and clean, or the capability is configured
	StatusGap        Status = "gap"         // observed and something was found
	StatusNotChecked Status = "not_checked" // we can answer this, but nothing is connected yet
	StatusNeedsYou   Status = "needs_you"   // only a human can answer; not yet attested
	StatusNotCovered Status = "not_covered" // we do not cover this
)

// Item is one practice.
type Item struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	Tier     Tier     `json:"tier"`
	Text     string   `json:"text"`
	Evidence Evidence `json:"evidence"`

	// Needs lists the asset types or connection kinds that must be present before an OBSERVED item
	// can be answered at all. Empty means it is answerable from whatever the tenant already has.
	Needs []string `json:"needs,omitempty"`
	// Tools names the OSS scanners that answer an OBSERVED item, so a customer can see what actually
	// runs rather than trusting a tick. Deterministic by design — the agents reason over the output,
	// they do not replace it.
	Tools []string `json:"tools,omitempty"`
	// GapRules are finding rule-id or tool prefixes whose presence means this practice has a gap.
	GapRules []string `json:"-"`

	// Instead names what a customer should use for an UNBUILT item. Pointing at a competitor's tool
	// is cheaper than the trust cost of implying we do it.
	Instead string `json:"instead,omitempty"`
	// Why explains an ATTESTED item — what we would need to see to answer it ourselves.
	Why string `json:"why,omitempty"`
	// Agent names which of the two agents owns this practice, so the row routes to the one that can
	// actually act on it: the engineer proposes fixes for what a scanner found, the pentester proves
	// which of them an attacker can really reach. A row owned by neither is infrastructure or process.
	Agent string `json:"agent,omitempty"`
}

// Result is an item plus its resolved status for a tenant.
type Result struct {
	Item
	Status Status `json:"status"`
	// Detail is the one-line reason for the status, in the user's terms.
	Detail string `json:"detail"`
	// GapCount is how many live findings drive a StatusGap.
	GapCount int `json:"gap_count,omitempty"`
	// AttestedBy/AttestedAt record who answered an ATTESTED item.
	AttestedBy string `json:"attested_by,omitempty"`
	AttestedAt string `json:"attested_at,omitempty"`
}

// Input is the tenant state the assessment reads. Everything is real stored state — nothing here is
// inferred or predicted.
type Input struct {
	Stage Tier
	// AssetTypes present in the tenant (container_image, repository, web_application, …).
	AssetTypes map[string]bool
	// ConnKinds of ACTIVE connections (github, aws, gworkspace, …). Inactive ones do not count:
	// the runner skips their assets, so counting them would claim coverage that is not happening.
	ConnKinds map[string]bool
	// FindingKeys are `tool` and `rule_id` values from the tenant's live findings, used to detect gaps.
	FindingTools map[string]int
	FindingRules map[string]int
	// Capabilities that are switched on for this tenant (sla_configured, pr_bot_enabled, …).
	Capabilities map[string]bool
	// Attestations answers ATTESTED items, keyed by item id.
	Attestations map[string]Attestation
}

// Attestation is a human's answer to something no scan can see.
type Attestation struct {
	Answered bool   `json:"answered"`
	InPlace  bool   `json:"in_place"`
	By       string `json:"by"`
	At       string `json:"at"`
	Note     string `json:"note,omitempty"`
}

// Assess resolves every item in scope for the tenant's stage.
func Assess(in Input) []Result {
	stage := in.Stage
	if !stage.Valid() {
		stage = TierSeed
	}
	out := make([]Result, 0, len(Items()))
	for _, it := range Items() {
		if !stage.Includes(it.Tier) {
			continue
		}
		out = append(out, resolve(it, in))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return tierOrder[out[i].Tier] < tierOrder[out[j].Tier]
	})
	return out
}

func resolve(it Item, in Input) Result {
	r := Result{Item: it}
	switch it.Evidence {
	case EvidenceUnbuilt:
		r.Status = StatusNotCovered
		r.Detail = "We don't cover this."
		if it.Instead != "" {
			r.Detail += " " + it.Instead
		}

	case EvidenceAttested:
		a := in.Attestations[it.ID]
		switch {
		case !a.Answered:
			r.Status = StatusNeedsYou
			r.Detail = it.Why
		case a.InPlace:
			r.Status = StatusPass
			r.Detail = "Confirmed by " + a.By
			r.AttestedBy, r.AttestedAt = a.By, a.At
		default:
			r.Status = StatusGap
			r.Detail = a.By + " recorded this as not in place"
			r.AttestedBy, r.AttestedAt = a.By, a.At
		}

	case EvidenceCapability:
		if in.Capabilities[it.ID] {
			r.Status = StatusPass
			r.Detail = "Switched on for this workspace."
		} else {
			r.Status = StatusNotChecked
			r.Detail = "Available, not yet switched on."
		}

	default: // EvidenceObserved
		n := countGaps(it.GapRules, in)
		// FINDINGS ARE PROOF THE CHECK RAN. The Needs gate exists to separate "clean" from "never
		// looked", so it must not suppress a row a detector has already answered — a posted SaaS
		// posture snapshot produces real findings without any connection of that kind existing, and
		// gating on Needs first reported those as unchecked while the gaps sat in the store.
		if n == 0 && !hasAny(it.Needs, in.AssetTypes, in.ConnKinds) {
			r.Status = StatusNotChecked
			// Never PASS on an empty estate. "We looked and it was clean" and "we never looked" are
			// different claims, and this row is the second one.
			r.Detail = "Connect " + humanNeeds(it.Needs) + " and this is checked on every scan."
			break
		}
		if n > 0 {
			r.Status, r.GapCount = StatusGap, n
			r.Detail = plural(n, "open finding", "open findings") + " from " + strings.Join(it.Tools, ", ")
		} else {
			r.Status = StatusPass
			r.Detail = "Checked by " + strings.Join(it.Tools, ", ") + " — nothing open."
		}
	}
	return r
}

// hasAny reports whether the tenant has at least one of the asset types or connection kinds an
// observed item needs. No requirement means it is answerable from whatever exists.
func hasAny(needs []string, assets, conns map[string]bool) bool {
	if len(needs) == 0 {
		return true
	}
	for _, n := range needs {
		if assets[n] || conns[n] {
			return true
		}
	}
	return false
}

// Matches reports whether a finding belongs to this practice. Exported so a caller can select the
// exact findings behind a gap row and hand them to the remediation proposer — the row is only
// actionable if we can say WHICH findings it is made of.
func Matches(it Item, tool, ruleID string) bool {
	for _, p := range it.GapRules {
		if tool == p || strings.HasPrefix(ruleID, p) {
			return true
		}
	}
	return false
}

func countGaps(prefixes []string, in Input) int {
	n := 0
	for _, p := range prefixes {
		for tool, c := range in.FindingTools {
			if tool == p {
				n += c
			}
		}
		for rule, c := range in.FindingRules {
			if strings.HasPrefix(rule, p) {
				n += c
			}
		}
	}
	return n
}

func humanNeeds(needs []string) string {
	pretty := map[string]string{
		"repository": "a code repository", "container_image": "a container image",
		"web_application": "a web app", "api": "an API", "domain": "a domain",
		"ip_address": "an IP range", "cloud_account": "a cloud account",
		"github": "GitHub", "aws": "AWS", "gcp": "GCP", "azure": "Azure",
		"gworkspace": "Google Workspace", "m365": "Microsoft 365", "okta": "Okta",
		"workspace": "your identity provider",
	}
	seen := map[string]bool{}
	var parts []string
	for _, n := range needs {
		label := pretty[n]
		if label == "" {
			label = n
		}
		if !seen[label] {
			seen[label] = true
			parts = append(parts, label)
		}
	}
	switch len(parts) {
	case 0:
		return "a system"
	case 1:
		return parts[0]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1]
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Summary is the roll-up a CTO reads first.
type Summary struct {
	Stage      Tier `json:"stage"`
	Total      int  `json:"total"`
	Pass       int  `json:"pass"`
	Gap        int  `json:"gap"`
	NotChecked int  `json:"not_checked"`
	NeedsYou   int  `json:"needs_you"`
	NotCovered int  `json:"not_covered"`
}

// Summarize counts the resolved items. Deliberately does NOT produce a single percentage: rolling
// "we never looked" together with "we looked and it was clean" into one number is exactly the
// false-comfort this package exists to avoid.
func Summarize(stage Tier, rs []Result) Summary {
	s := Summary{Stage: stage, Total: len(rs)}
	for _, r := range rs {
		switch r.Status {
		case StatusPass:
			s.Pass++
		case StatusGap:
			s.Gap++
		case StatusNotChecked:
			s.NotChecked++
		case StatusNeedsYou:
			s.NeedsYou++
		case StatusNotCovered:
			s.NotCovered++
		}
	}
	return s
}

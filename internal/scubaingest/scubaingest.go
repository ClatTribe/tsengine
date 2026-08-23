// Package scubaingest correlates a customer's own ScubaGear/ScubaGoggles run against ours.
//
// WHY INGEST RATHER THAN WRAP. §13 says wrap the OSS tool, and identity was the one surface where we
// did not. But the audit that flagged it also showed the gap is PROVENANCE, not coverage: our SCuBA
// recall is 0.993 (145/146 detectable, 100/101 SHALL) and every mapping is EXECUTION-PROVEN — the
// bench builds a violating snapshot, runs the real assessor, and fails if the rule does not fire.
// Running ScubaGear ourselves would add a PowerShell + Graph-modules runtime to the sandbox and a
// second credential ask, to obtain a second opinion about detections we can already demonstrate.
//
// Ingesting their run costs neither. ScubaGear is CISA's tool and federal civilian agencies are
// directed to run it, so many tenants already have a ScubaResults JSON. Correlating it with ours
// gives the thing wrapping was actually for — independent corroboration from the authority that
// publishes the baseline — and it follows the pattern the rest of this platform already uses
// (/v1/osint/ingest, /v1/tprm/ingest): the posted artifact works today, a live fetch is the
// credential-gated half.
//
// # The field-name problem, handled rather than guessed
//
// CISA documents the SEMANTIC fields — Control ID, Requirement, Result (Pass/Fail/Warning/Error/
// Omitted), Criticality — but not their verbatim JSON casing, and the published docs contain no
// example. Go's encoding/json is case-insensitive but NOT separator-insensitive, so a struct tag
// betting on one spelling silently matches nothing (the exact bug CLAUDE.md records for
// nuclei_template). So the resolver tries the documented spellings explicitly and is tested against
// all of them.
//
// And the guard that makes that safe: AN INGEST THAT RECOGNISES ZERO POLICIES SAYS SO. Reporting a
// file we could not parse as a tenant with no failures is the worst possible direction for this
// error — it would turn our inability to read CISA's output into a clean bill of health.
package scubaingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Outcome is a normalized ScubaGear result for one policy.
type Outcome struct {
	PolicyID    string `json:"policy_id"`
	Requirement string `json:"requirement,omitempty"`
	// Result is the normalized verdict: pass | fail | warning | error | omitted.
	Result string `json:"result"`
	// Criticality is CISA's own ("Shall", "Should", ...), kept verbatim.
	Criticality string `json:"criticality,omitempty"`
	Details     string `json:"details,omitempty"`
}

// Failed reports whether CISA's tool considered this policy violated. Only an explicit Fail counts:
// a Warning is an advisory, and Error/Omitted mean their tool could not judge it — folding either
// into a failure would attribute to CISA a verdict CISA declined to give.
func (o Outcome) Failed() bool { return o.Result == "fail" }

// Judged reports whether their run reached a verdict at all. Error and Omitted did not, and a
// correlation must not read them as agreement.
func (o Outcome) Judged() bool { return o.Result == "pass" || o.Result == "fail" }

// ErrNoPoliciesRecognized is returned when a document parsed as JSON but yielded no policy results.
//
// Loud by design. The realistic causes are a field spelling we do not handle, a wrong file, or a
// truncated upload — and all of them would otherwise render as a tenant with nothing wrong.
var ErrNoPoliciesRecognized = errors.New(
	"scubaingest: no policy results recognized in this document — it parsed as JSON but no entry " +
		"carried a recognizable SCuBA policy id (MS.AAD.1.1v1 / GWS.GMAIL.1.1v1 form). This is " +
		"reported rather than treated as a clean tenant: a file we cannot read must never become a " +
		"pass. Check it is a ScubaGear/ScubaGoggles results JSON, and if the field names differ from " +
		"the ones handled here, add the spelling rather than assuming zero findings")

// policyID matches the SCuBA identifier form used by both tools: MS.<PRODUCT>.<n>.<n>v<n> for M365,
// GWS.<PRODUCT>.<n>.<n>v<n> for Google Workspace. Anchored so a policy id inside prose is not lifted.
var policyID = regexp.MustCompile(`^(MS|GWS)\.[A-Z0-9]+\.\d+\.\d+v\d+$`)

// fieldAliases are the spellings each semantic field may appear under. CISA documents the fields and
// not their casing, so the ambiguity is enumerated rather than bet on — and TestParse_AcceptsEvery
// DocumentedSpelling drives all of them.
var fieldAliases = map[string][]string{
	"id":          {"ControlID", "controlId", "control_id", "PolicyId", "policyId", "policy_id", "Control", "Id"},
	"requirement": {"Requirement", "requirement", "RequirementText", "requirement_text"},
	"result":      {"Result", "result", "Status", "status"},
	"criticality": {"Criticality", "criticality", "Severity", "severity"},
	"details":     {"Details", "details", "ReportDetails", "report_details"},
}

// Parse walks an arbitrary ScubaResults document and lifts every policy result it can recognize.
//
// Structure-agnostic on purpose: the results are nested by product and policy group, and that nesting
// is exactly the part the docs do not pin down. Walking for objects that carry a recognizable policy
// id is robust to a layout change in a way a hand-modelled struct is not.
func Parse(raw []byte) ([]Outcome, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("scubaingest: not valid JSON: %w", err)
	}
	var out []Outcome
	walk(doc, &out)
	if len(out) == 0 {
		return nil, ErrNoPoliciesRecognized
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PolicyID < out[j].PolicyID })
	return out, nil
}

func walk(node any, out *[]Outcome) {
	switch v := node.(type) {
	case map[string]any:
		if o, ok := outcomeFrom(v); ok {
			*out = append(*out, o)
			return // a policy result is a leaf; do not also mine its children
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic order, so a corpus diffs cleanly
		for _, k := range keys {
			walk(v[k], out)
		}
	case []any:
		for _, e := range v {
			walk(e, out)
		}
	}
}

func outcomeFrom(m map[string]any) (Outcome, bool) {
	id := strings.TrimSpace(pick(m, "id"))
	if !policyID.MatchString(id) {
		return Outcome{}, false
	}
	return Outcome{
		PolicyID:    id,
		Requirement: pick(m, "requirement"),
		Result:      normalizeResult(pick(m, "result")),
		Criticality: pick(m, "criticality"),
		Details:     pick(m, "details"),
	}, true
}

func pick(m map[string]any, field string) string {
	for _, alias := range fieldAliases[field] {
		if s, ok := m[alias].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// normalizeResult maps CISA's verdicts onto ours. An unrecognized value becomes "error" — NOT a pass:
// a verdict we do not understand is one we cannot claim they gave.
func normalizeResult(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pass", "passed", "true":
		return "pass"
	case "fail", "failed", "false":
		return "fail"
	case "warning", "warn":
		return "warning"
	case "omit", "omitted", "n/a", "not applicable":
		return "omitted"
	default:
		return "error"
	}
}

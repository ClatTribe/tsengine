// Package apiexposure detects OWASP API3:2023 — Broken Object Property Level
// Authorization, in its "excessive data exposure" form: an endpoint returns fields
// the caller should never have received.
//
// IT WRITES NO CLASSIFIER. The question "does this field hold personal data, card
// data, or a credential?" is already answered by internal/dataclass, which Luhn- and
// range-checks structure rather than shape, ranks a value signal above a name signal,
// refuses to treat an object's NAME as evidence, and emits evidence that never echoes
// a raw value. An API response is the same shape dataclass already takes — the
// endpoint is the object, the JSON fields are the columns — so this package is the
// glue. A second field classifier beside a mutation-tested one would be the §13
// violation, not the fix.
//
// THE GROUNDING LINE (§10), which is what makes this shippable rather than a noise
// generator: returning personal data is not by itself a defect. A user's own profile
// endpoint returns their own email, correctly, and a scanner that flags it teaches
// people to ignore scanners. So the verdict is conditional on something OBSERVED
// rather than guessed — whether the request that produced the body carried any
// credentials, which the caller knows because it controls what it sent:
//
//   - secret / auth  → a finding REGARDLESS of authentication. No API should return
//     a password hash, a private key or a session token in any body, to anyone.
//   - pii / phi / pci → a finding only when the response came back UNAUTHENTICATED.
//     Otherwise it is recorded as an observation, not a vulnerability.
//
// What this deliberately cannot see: whether an authenticated caller received
// SOMEONE ELSE'S personal data. That is object-level authorization — API1 — and it
// needs two identities to prove, which is internal/apiauthz's differential test.
// Guessing at it from one response is exactly the overclaim §10 forbids.
package apiexposure

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/dataclass"
	"github.com/ClatTribe/tsengine/pkg/types"
)

const (
	// RulePrefix namespaces every finding this package emits.
	RulePrefix = "apiexposure::"
	// RuleUnauthPersonal is personal data returned to an unauthenticated caller.
	RuleUnauthPersonal = RulePrefix + "unauthenticated-personal-data"
	// RuleCredential is a credential or token in a response body, authenticated or not.
	RuleCredential = RulePrefix + "credential-in-response"
	// RuleObservation records classified data returned to an AUTHENTICATED caller. Not a
	// vulnerability — the caller may be entitled to it — but recorded so the reader can see
	// what the endpoint returns and disagree.
	RuleObservation = RulePrefix + "authenticated-data-observation"

	// maxSampleValues caps how many values per field reach the classifier. dataclass takes a
	// SAMPLE by contract, and a large array must not turn one response into a huge object.
	maxSampleValues = 10
	// maxFields bounds a pathological response (a map with thousands of keys) so one body
	// cannot dominate a scan.
	maxFields = 200
)

// Response is one observed API response. Authenticated says whether the REQUEST that
// produced it carried any credential — the caller knows, because it sent it.
type Response struct {
	Endpoint      string
	Status        int
	Body          string
	Authenticated bool
}

// Assess classifies each response body and returns findings under the rules above.
// A body that is not JSON, is empty, or classifies to nothing yields nothing — a
// clean API produces zero findings.
func Assess(responses []Response) []types.SandboxEmittedFinding {
	var out []types.SandboxEmittedFinding
	for _, r := range responses {
		cols := columnsFromJSON(r.Body)
		if len(cols) == 0 {
			continue
		}
		// The object NAME is deliberately the endpoint and is never used as evidence:
		// dataclass ignores it by design, and an endpoint called /users is not proof of
		// anything about what it returns.
		res := dataclass.Classify(dataclass.Object{Name: r.Endpoint, Columns: cols})
		if !res.Sensitive() {
			continue
		}
		if f, ok := finding(r, res); ok {
			out = append(out, f)
		}
	}
	return out
}

// finding applies the grounding line to one classified response.
func finding(r Response, res dataclass.Result) (types.SandboxEmittedFinding, bool) {
	credential := false
	var personal []string
	for _, c := range res.Classes {
		switch c {
		case dataclass.ClassSecret, dataclass.ClassAuth:
			credential = true
		default:
			personal = append(personal, string(c))
		}
	}

	switch {
	case credential:
		return types.SandboxEmittedFinding{
			RuleID:      RuleCredential,
			Tool:        "apiexposure",
			Severity:    types.SeverityHigh,
			CWE:         []string{"CWE-200"},
			Endpoint:    r.Endpoint,
			Title:       "API response contains a credential",
			Description: describe(r, res, "A response body returned credential material. No API should return a password hash, key or token in a body, to any caller — authenticated or not."),
			ToolArgs:    map[string]string{"owasp_api": "API3", "authenticated": strconv.FormatBool(r.Authenticated)},
		}, true

	case len(personal) > 0 && !r.Authenticated:
		return types.SandboxEmittedFinding{
			RuleID:      RuleUnauthPersonal,
			Tool:        "apiexposure",
			Severity:    types.SeverityHigh,
			CWE:         []string{"CWE-200"},
			Endpoint:    r.Endpoint,
			Title:       fmt.Sprintf("Unauthenticated response exposes %s", strings.Join(personal, ", ")),
			Description: describe(r, res, "This body came back on a request that carried NO credentials, so anyone who can reach the endpoint receives it."),
			ToolArgs:    map[string]string{"owasp_api": "API3", "authenticated": "false"},
		}, true

	case len(personal) > 0:
		// Authenticated. The caller may well be entitled to this, so it is NOT called a
		// vulnerability — but it is recorded, because "we looked and said nothing" and "we
		// never looked" must not render identically. Whether the caller was entitled to
		// ANOTHER user's data is API1 and needs apiauthz's two identities to answer.
		return types.SandboxEmittedFinding{
			RuleID:      RuleObservation,
			Tool:        "apiexposure",
			Severity:    types.SeverityInfo,
			CWE:         []string{"CWE-200"},
			Endpoint:    r.Endpoint,
			Title:       fmt.Sprintf("Authenticated response returns %s", strings.Join(personal, ", ")),
			Description: describe(r, res, "Recorded, not flagged: an authenticated caller may be entitled to this. Whether they received data belonging to ANOTHER user is object-level authorization (API1), which needs a two-identity differential test to answer."),
			ToolArgs:    map[string]string{"owasp_api": "API3", "authenticated": "true"},
		}, true
	}
	return types.SandboxEmittedFinding{}, false
}

// describe renders the classifier's own evidence. dataclass guarantees the evidence
// names the field and how it matched and NEVER echoes a value, so a finding about
// personal data does not itself leak any.
func describe(r Response, res dataclass.Result, lead string) string {
	var b strings.Builder
	b.WriteString(lead)
	b.WriteString(fmt.Sprintf(" Endpoint returned HTTP %d.", r.Status))
	b.WriteString(" Evidence:")
	for _, m := range res.Matches {
		b.WriteString(fmt.Sprintf(" [%s/%s] %s;", m.Class, m.Confidence, m.Evidence))
	}
	return strings.TrimSuffix(b.String(), ";")
}

// columnsFromJSON flattens a JSON body into dataclass columns: leaf field name → a
// bounded sample of the values seen at that name.
//
// Names are collapsed across array elements on purpose — ten users each with an
// "email" become ONE column with ten sampled values, which is exactly the shape
// dataclass's value detectors need to reach Confirmed rather than Suspected. Keeping
// them as users[0].email … users[9].email would give every column a single value and
// systematically under-confirm.
func columnsFromJSON(body string) []dataclass.Column {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return nil // not JSON — nothing to classify, and guessing at a shape is not classification
	}
	acc := map[string][]string{}
	walk(v, "", acc, 0)
	if len(acc) == 0 {
		return nil
	}

	names := make([]string, 0, len(acc))
	for n := range acc {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic output; the scorer and the reader both benefit
	if len(names) > maxFields {
		names = names[:maxFields]
	}
	cols := make([]dataclass.Column, 0, len(names))
	for _, n := range names {
		cols = append(cols, dataclass.Column{Name: n, Values: acc[n]})
	}
	return cols
}

// maxDepth bounds recursion on a deeply nested or hostile body.
const maxDepth = 12

func walk(v any, name string, acc map[string][]string, depth int) {
	if depth > maxDepth {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			walk(child, k, acc, depth+1)
		}
	case []any:
		for _, child := range t {
			walk(child, name, acc, depth+1) // array elements share the parent's field name
		}
	case string:
		record(acc, name, t)
	case float64:
		record(acc, name, strconv.FormatFloat(t, 'f', -1, 64))
	case bool, nil:
		// A boolean or null carries no classifiable value, but the NAME still matters —
		// a field called "password" that is null is still a field called "password".
		record(acc, name, "")
	}
}

func record(acc map[string][]string, name, val string) {
	if name == "" {
		return
	}
	cur := acc[name]
	if val != "" && len(cur) < maxSampleValues {
		cur = append(cur, val)
	}
	if cur == nil {
		cur = []string{} // present with no sampled values: dataclass can still match the NAME
	}
	acc[name] = cur
}

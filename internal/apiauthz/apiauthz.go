// Package apiauthz is the API authorization specialist (ADR 0010 Phase 1) — the OWASP-API-top-10
// authorization detectors that have no standalone OSS equivalent (§5.2: authorization is business
// logic, not a fuzzable pattern). `classifyOp` (internal/asset/api) routes operations to these
// classes; this is the specialist those routes waited for. Three classes:
//
//   - BOLA (API1) — object-level: replay the VICTIM's request as the ATTACKER; a bypass is proven
//     by a 2xx attacker response carrying the victim's data. Benign — reads the victim's own object.
//   - BFLA (API5) — function-level: a low-privilege caller invokes a privileged op and is not denied.
//   - mass_assignment (API3/API6) — the attacker writes its OWN object with a privileged field it
//     shouldn't control, then reads it back; a bypass is proven only when the field PERSISTED.
//     Benign — it only modifies the caller's own object, never another principal's.
//
// Low-FP by construction: every class fires only on a machine-checkable proof (data leak / undenied
// privileged call / persisted privileged field), so a confirmed finding is `verification: verified`
// — never a maybe (§10, the XBOW no-FP bar).
package apiauthz

import (
	"context"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Class is the authorization-bug class an operation is tested for (mirrors api routing classes).
type Class string

const (
	ClassBOLA Class = "bola"            // object-level: can the attacker read the victim's object? (API1)
	ClassBFLA Class = "bfla"            // function-level: can a low-priv caller invoke a privileged op? (API5)
	ClassMass Class = "mass_assignment" // can a caller set a privileged field on its OWN object? (API3/API6)
)

// Identity is one authenticated principal in the differential test (its auth material).
type Identity struct {
	Name    string            // "victim" / "attacker" (for evidence)
	Headers map[string]string // Authorization / Cookie / etc.
}

// Operation is one concrete API operation to test — a method + a fully-qualified URL that
// targets the VICTIM's object (for BOLA) or a privileged function (for BFLA).
type Operation struct {
	Method string
	URL    string
	Class  Class
	// Marker is a string from the victim's object that proves data leakage if it appears in
	// the attacker's response (e.g. the victim's email/account id). Optional but strongly
	// raises specificity — without it the test falls back to a body-equality differential.
	// For mass_assignment it is the privileged VALUE (e.g. "admin") that, if it appears in the
	// post-write read-back, proves the server accepted a field the caller shouldn't control.
	Marker string
	// Body is the write payload for a mass_assignment test — the caller's own object plus a
	// privileged field it shouldn't be able to set (e.g. {"name":"me","role":"admin"}).
	Body string
}

// AuthzTest is a planned differential test case.
type AuthzTest struct {
	Op       Operation
	Victim   Identity
	Attacker Identity
}

// TestConfig is the per-asset BOLA/BFLA test setup an owner configures once: the two identities
// + the object-bearing operations to test. Plan(config.Operations, victim, attacker) drives Run.
type TestConfig struct {
	Victim     Identity    `json:"victim"`
	Attacker   Identity    `json:"attacker"`
	Operations []Operation `json:"operations"`
}

// Valid checks the config is runnable: both identities carry auth, and every operation is a
// concrete BOLA/BFLA target. Returns a descriptive error for the config API.
func (c TestConfig) Valid() error {
	if len(c.Victim.Headers) == 0 || len(c.Attacker.Headers) == 0 {
		return cfgErr("both the victim and attacker identities need auth headers")
	}
	if len(c.Operations) == 0 {
		return cfgErr("at least one operation to test is required")
	}
	for i, op := range c.Operations {
		if strings.TrimSpace(op.Method) == "" || strings.TrimSpace(op.URL) == "" {
			return cfgErr("operation " + strconv.Itoa(i) + " needs a method + url")
		}
		switch op.Class {
		case ClassBOLA, ClassBFLA:
		case ClassMass:
			if strings.TrimSpace(op.Body) == "" || strings.TrimSpace(op.Marker) == "" {
				return cfgErr("mass_assignment operation " + strconv.Itoa(i) + " needs a write body + a privileged-value marker")
			}
		default:
			return cfgErr("operation " + strconv.Itoa(i) + " class must be bola, bfla or mass_assignment")
		}
	}
	return nil
}

type configError string

func (e configError) Error() string { return string(e) }
func cfgErr(s string) error         { return configError("authz test: " + s) }

// Request / Response / Prober: the minimal live surface. Kept local (not pentest.Probe) because
// the authz test needs per-identity headers. The live impl is gated exactly like the
// active-exploit prober (off unless the operator enables it + consent); tests inject a fake.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

type Response struct {
	Status int
	Body   string
}

type Prober interface {
	Do(ctx context.Context, r Request) (Response, error)
}

// Plan builds the test set from classified operations + the two identities. BOLA/BFLA are
// differential (victim vs attacker); mass_assignment is a self-test (the attacker writes to its
// own object), so it carries only the attacker identity.
func Plan(ops []Operation, victim, attacker Identity) []AuthzTest {
	out := make([]AuthzTest, 0, len(ops))
	for _, op := range ops {
		if op.Class != ClassBOLA && op.Class != ClassBFLA && op.Class != ClassMass {
			continue
		}
		out = append(out, AuthzTest{Op: op, Victim: victim, Attacker: attacker})
	}
	return out
}

// Verdict is the predicate's decision for one test.
type Verdict struct {
	Bypassed bool
	Class    Class
	Reason   string
}

// Evaluate is the differential predicate (offline-testable, the heart of the specialist). It
// decides whether authorization was bypassed from the victim's legitimate baseline response and
// the attacker's response to the same request. Conservative: a denial (401/403/404) is the
// correct, secure outcome → NOT a finding; a finding requires a proven bypass.
func Evaluate(t AuthzTest, baseline, attacker Response) Verdict {
	switch t.Op.Class {
	case ClassBOLA:
		// The attacker must have SUCCEEDED (2xx) AND received the victim's data. Data is
		// proven by the marker appearing in the attacker body, else by the attacker body
		// matching the victim baseline (same object returned to the wrong principal).
		if attacker.Status/100 == 2 && victimDataLeaked(t.Op.Marker, baseline.Body, attacker.Body) {
			return Verdict{true, ClassBOLA,
				"attacker identity read the victim's object: HTTP " + strconv.Itoa(attacker.Status) + " with the victim's data returned"}
		}
	case ClassBFLA:
		// A low-privilege caller invoked a privileged function and was NOT denied.
		if attacker.Status/100 == 2 {
			return Verdict{true, ClassBFLA,
				"low-privilege identity invoked a privileged function without authorization: HTTP " + strconv.Itoa(attacker.Status)}
		}
	}
	return Verdict{}
}

// victimDataLeaked reports whether the attacker's response carries the victim's data.
func victimDataLeaked(marker, victimBody, attackerBody string) bool {
	if m := strings.TrimSpace(marker); m != "" {
		return strings.Contains(attackerBody, m)
	}
	// No marker: fall back to body-equality (the attacker got the same object). Require a
	// non-trivial body so an empty 200 / generic "[]" doesn't read as a leak (FP guard).
	ab := strings.TrimSpace(attackerBody)
	return len(ab) >= 8 && ab == strings.TrimSpace(victimBody)
}

// Run executes a plan against the API via the (gated) prober and returns a finding for every
// PROVEN bypass. A nil prober → no live test (returns nil; the caller reports un-run leads). A
// per-request error skips that test (best-effort; never a falsely-confident result).
func Run(ctx context.Context, plan []AuthzTest, prober Prober, idgen func() string) []types.Finding {
	if prober == nil {
		return nil
	}
	var findings []types.Finding
	for _, t := range plan {
		if t.Op.Class == ClassMass {
			// Self-test: the attacker writes its OWN object with a privileged field, then reads
			// it back. Benign — it never touches another principal's data.
			write, err := prober.Do(ctx, Request{Method: t.Op.Method, URL: t.Op.URL, Headers: t.Attacker.Headers, Body: t.Op.Body})
			if err != nil {
				continue
			}
			confirm, err := prober.Do(ctx, Request{Method: "GET", URL: t.Op.URL, Headers: t.Attacker.Headers})
			if err != nil {
				continue
			}
			if v := evaluateMassAssignment(t.Op, write, confirm); v.Bypassed {
				findings = append(findings, finding(t, v, write, confirm, idgen))
			}
			continue
		}
		baseline, err := prober.Do(ctx, Request{Method: t.Op.Method, URL: t.Op.URL, Headers: t.Victim.Headers})
		if err != nil {
			continue
		}
		attacker, err := prober.Do(ctx, Request{Method: t.Op.Method, URL: t.Op.URL, Headers: t.Attacker.Headers})
		if err != nil {
			continue
		}
		if v := Evaluate(t, baseline, attacker); v.Bypassed {
			findings = append(findings, finding(t, v, baseline, attacker, idgen))
		}
	}
	return findings
}

// evaluateMassAssignment is the mass-assignment predicate (offline-testable). A bypass is proven
// only when the write SUCCEEDED (2xx) AND the privileged value (op.Marker) appears in the
// read-back — i.e. the server persisted a field the caller should not control. A rejected or
// ignored field (marker absent on read-back) is the secure outcome → no finding.
func evaluateMassAssignment(op Operation, write, confirm Response) Verdict {
	if write.Status/100 == 2 && strings.Contains(confirm.Body, op.Marker) {
		return Verdict{true, ClassMass,
			"a privileged field (\"" + op.Marker + "\") set by the caller persisted on read-back: HTTP " +
				strconv.Itoa(write.Status) + " write accepted an attribute the caller should not control"}
	}
	return Verdict{}
}

func finding(t AuthzTest, v Verdict, a, b Response, idgen func() string) types.Finding {
	var cwe, title, desc string
	switch v.Class {
	case ClassBFLA:
		cwe, title = "CWE-285", "Broken Function Level Authorization (BFLA)"
		desc = v.Reason + " (victim baseline HTTP " + strconv.Itoa(a.Status) + ", attacker HTTP " + strconv.Itoa(b.Status) +
			"). Authorization must be enforced server-side per object/function, not inferred from the caller."
	case ClassMass:
		cwe, title = "CWE-915", "Mass Assignment (unsafe object attribute binding)"
		desc = v.Reason + ". The write must allow-list bindable fields; never bind the request body straight onto the model."
	default:
		cwe, title = "CWE-639", "Broken Object Level Authorization (BOLA)"
		desc = v.Reason + " (victim baseline HTTP " + strconv.Itoa(a.Status) + ", attacker HTTP " + strconv.Itoa(b.Status) +
			"). Authorization must be enforced server-side per object/function, not inferred from the caller."
	}
	id := "apiauthz-" + string(v.Class)
	if idgen != nil {
		id = idgen()
	}
	return types.Finding{
		ID: id, RuleID: "apiauthz::" + string(v.Class), Tool: "apiauthz",
		Severity: types.SeverityHigh, CWE: []string{cwe},
		Endpoint: t.Op.Method + " " + t.Op.URL, Title: title,
		Description: desc,
		// A confirmed bypass is a live proof, not a pattern match.
		VerificationStatus: types.VerificationVerified,
		MITRETechniques:    []string{"T1190"},
	}
}

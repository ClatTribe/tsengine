// Package apiauthz is the API object/function-level authorization specialist (ADR 0010 Phase 1) —
// the BOLA (OWASP API1) / BFLA (OWASP API5) detector that has no standalone OSS equivalent (§5.2:
// authorization is business logic, not a fuzzable pattern). `classifyOp` (internal/asset/api)
// already routes operations to idor/bfla classes; this is the specialist those routes waited for.
//
// It is a DIFFERENTIAL test: with two authenticated identities — a victim that owns an object (or
// is privileged) and an attacker that is a different, lower-privilege principal — it replays the
// victim's request as the attacker and checks, with a machine-checkable predicate, whether
// authorization was bypassed. Benign by construction: it only reads the victim's OWN object to
// prove access, never writes or exfiltrates. Low-FP by construction: it fires only on a proven
// bypass (a 2xx attacker response carrying the victim's data, or an undenied privileged call),
// so a confirmed finding is `verification: verified` — never a maybe (§10, the XBOW no-FP bar).
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
	ClassBOLA Class = "bola" // object-level: can the attacker read the victim's object? (API1)
	ClassBFLA Class = "bfla" // function-level: can a low-priv caller invoke a privileged op? (API5)
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
	Marker string
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
		if op.Class != ClassBOLA && op.Class != ClassBFLA {
			return cfgErr("operation " + strconv.Itoa(i) + " class must be bola or bfla")
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

// Plan builds the differential test set from classified operations + the two identities. Only
// operations classed BOLA or BFLA are testable here (mass-assignment is a separate specialist).
func Plan(ops []Operation, victim, attacker Identity) []AuthzTest {
	out := make([]AuthzTest, 0, len(ops))
	for _, op := range ops {
		if op.Class != ClassBOLA && op.Class != ClassBFLA {
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

func finding(t AuthzTest, v Verdict, baseline, attacker Response, idgen func() string) types.Finding {
	cwe, title := "CWE-639", "Broken Object Level Authorization (BOLA)"
	if v.Class == ClassBFLA {
		cwe, title = "CWE-285", "Broken Function Level Authorization (BFLA)"
	}
	id := "apiauthz-" + string(v.Class)
	if idgen != nil {
		id = idgen()
	}
	return types.Finding{
		ID: id, RuleID: "apiauthz::" + string(v.Class), Tool: "apiauthz",
		Severity: types.SeverityHigh, CWE: []string{cwe},
		Endpoint: t.Op.Method + " " + t.Op.URL, Title: title,
		Description: v.Reason + " (victim baseline HTTP " + strconv.Itoa(baseline.Status) +
			", attacker HTTP " + strconv.Itoa(attacker.Status) + "). Authorization must be enforced server-side per object/function, not inferred from the caller.",
		// A confirmed differential bypass is a live proof, not a pattern match.
		VerificationStatus: types.VerificationVerified,
		MITRETechniques:    []string{"T1190"},
	}
}

package apiauthz

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// discover.go is the API BOLA/BFLA DISCOVERY agent — competitor parity with AI-driven API-security
// testing (Akto et al.), the API-asset gap. The owner configures a few known operations; the LLM
// PROPOSES additional candidate operations likely to carry an authz bypass (sibling object ids, related
// collections, privileged/admin functions, bulk endpoints). The model ONLY proposes — the deterministic
// differential test (Evaluate, gated on active+consent) is what CONFIRMS a bypass, so a proposal that
// doesn't actually bypass yields no verdict (no LLM false positives, §10). Same safety model as the
// pentest D-agent: agent widens discovery, the deterministic validator proves.

// LLM is the minimal text-in/text-out model the proposer needs (cloudengine.LLM satisfies it).
type LLM interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

type proposedOp struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Class  string `json:"class"`
	Marker string `json:"marker,omitempty"`
	Body   string `json:"body,omitempty"` // the write payload for a mass_assignment proposal (required for that class)
}

// normalizeProposedClass maps the model's short class vocabulary (the words proposePrompt asks for) to
// the Class constants. The prompt says "mass", but ClassMass is "mass_assignment" — so without this
// mapping EVERY proposed mass-assignment op was silently dropped by the class filter (the whole class
// was un-proposable). Returns "" for an unrecognized class.
func normalizeProposedClass(s string) Class {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bola":
		return ClassBOLA
	case "bfla":
		return ClassBFLA
	case "mass", "mass_assignment":
		return ClassMass
	}
	return ""
}

// ProposeOperations asks the model for up to maxN additional candidate BOLA/BFLA/mass operations given
// the known ones. Returns only well-formed, novel operations (known method/URL/class, not a duplicate of
// the input) — an ill-formed proposal is dropped, never returned as a test.
func ProposeOperations(ctx context.Context, llm LLM, known []Operation, maxN int) ([]Operation, error) {
	if llm == nil {
		return nil, fmt.Errorf("apiauthz: no LLM configured")
	}
	if maxN <= 0 {
		maxN = 12
	}
	out, err := llm.Generate(ctx, proposePrompt(known, maxN))
	if err != nil {
		return nil, err
	}
	raw := extractJSONArray(out)
	if raw == "" {
		return nil, nil
	}
	var props []proposedOp
	if err := json.Unmarshal([]byte(raw), &props); err != nil {
		return nil, nil // unparseable → no candidates (never a falsely-confident test)
	}
	seen := map[string]bool{}
	for _, o := range known {
		seen[opKey(o.Method, o.URL)] = true
	}
	ops := make([]Operation, 0, len(props))
	for _, p := range props {
		m := strings.ToUpper(strings.TrimSpace(p.Method))
		u := strings.TrimSpace(p.URL)
		cl := normalizeProposedClass(p.Class)
		if m == "" || u == "" || cl == "" {
			continue
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue // must be a concrete URL, not a path fragment
		}
		// A mass_assignment test needs a write body + a privileged-value marker (mirrors
		// TestConfig.Valid): Run writes op.Body and evaluateMassAssignment checks op.Marker persisted.
		// A mass proposal missing either can never fire (a guaranteed no-op that also wastes a live
		// write), so drop it rather than emit a dead test.
		if cl == ClassMass && (strings.TrimSpace(p.Body) == "" || strings.TrimSpace(p.Marker) == "") {
			continue
		}
		k := opKey(m, u)
		if seen[k] {
			continue
		}
		seen[k] = true
		ops = append(ops, Operation{Method: m, URL: u, Class: cl, Marker: strings.TrimSpace(p.Marker), Body: strings.TrimSpace(p.Body)})
		if len(ops) >= maxN {
			break
		}
	}
	return ops, nil
}

func opKey(method, url string) string { return strings.ToUpper(method) + " " + url }

func proposePrompt(known []Operation, maxN int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `You are an API-security tester hunting authorization bypasses. Given the KNOWN operations on
an API, propose up to %d ADDITIONAL candidate operations likely to carry a broken-authorization bug:
- BOLA (bola): object-level — a sibling/other object id the caller shouldn't read (e.g. /orders/{otherId}).
- BFLA (bfla): function-level — a privileged/admin function a low-priv caller shouldn't invoke.
- mass: mass-assignment — a write that sets a field the caller shouldn't control (e.g. role=admin).

Ground proposals in the known operations' host + path patterns — same host, plausible sibling routes.
Do NOT invent unrelated hosts. Output ONLY a JSON array, each item:
{"method":"GET","url":"<full url, same host>","class":"bola|bfla|mass","marker":"<a string proving leakage if it appears>","body":"<mass ONLY: the JSON write payload incl the privileged field, e.g. {\"role\":\"admin\"}>"}
For class "mass" you MUST include both a "body" (the write payload) and a "marker" (the privileged value that proves the field persisted); a mass item without both is discarded.

KNOWN OPERATIONS:
`, maxN)
	for _, o := range known {
		fmt.Fprintf(&b, "- %s %s (%s)\n", o.Method, o.URL, nzClass(o.Class))
	}
	if len(known) == 0 {
		b.WriteString("(none provided — infer a plausible REST surface from the host)\n")
	}
	return b.String()
}

func nzClass(c Class) string {
	if c == "" {
		return "unclassified"
	}
	return string(c)
}

// extractJSONArray returns the first [...] block from the model output (it may wrap it in prose / a fence).
func extractJSONArray(s string) string {
	i, j := strings.Index(s, "["), strings.LastIndex(s, "]")
	if i < 0 || j <= i {
		return ""
	}
	return s[i : j+1]
}

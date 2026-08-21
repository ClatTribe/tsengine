package bench

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/gcpiam"
)

// gcpprivesc.go scores the GCP escalation catalogue against an EXTERNAL answer key.
//
// AWS got one (BishopFox's IAM-Vulnerable) and immediately reported a 35-point gap
// against numbers we grade ourselves. GCP had none, so its catalogue had never been
// checked against anything but our own fixtures — which is the condition that produced
// the AWS gap in the first place.
//
// RhinoSecurityLabs/GCP-IAM-Privilege-Escalation is the published research behind the
// GCP half of our own catalogue (internal/gcpiam/privesc.go cites "the Rhino
// 'Privilege Escalation in GCP' set" in its own comment). Its PrivEscScanner ships the
// catalogue as a MACHINE-READABLE dict — {Method: {Permissions: [...], Scope: [...]}} —
// so the answer key needs no interpretation from us.
//
// The scanner's own semantics decide ours: it uses set.issubset, so a method's
// Permissions list is an AND. That is exactly gcpiam.Technique.All with one permission
// per group, which is why this comparison is meaningful rather than approximate.

// GCPMethod is one method from Rhino's catalogue and our verdict on it.
type GCPMethod struct {
	// Name is Rhino's name for the method — the answer, never an input.
	Name string
	// Permissions are the permissions their catalogue says the method requires.
	Permissions []string
	// Detected names the gcpiam techniques that fired when granted exactly those.
	Detected []string
	Found    bool
}

// GCPPrivescResult is the scorecard.
type GCPPrivescResult struct {
	Methods []GCPMethod
	Total   int
	Hits    int
}

// Recall is the share of Rhino's methods we detect.
func (r GCPPrivescResult) Recall() float64 {
	if r.Total == 0 {
		return 0
	}
	return float64(r.Hits) / float64(r.Total)
}

// Missed returns the methods we found nothing for.
func (r GCPPrivescResult) Missed() []GCPMethod {
	var out []GCPMethod
	for _, m := range r.Methods {
		if !m.Found {
			out = append(out, m)
		}
	}
	return out
}

var (
	// A method header sits at exactly four spaces of indentation in the scanner's dict.
	gcpMethodRe = regexp.MustCompile(`(?m)^ {4}'([A-Za-z0-9_]+)':\s*\{`)
	gcpPermsRe  = regexp.MustCompile(`(?s)'Permissions'\s*:\s*\[(.*?)\]`)
	gcpQuoted   = regexp.MustCompile(`'([^']+)'`)
)

// ParseRhinoCatalogue reads the method → required-permissions map out of Rhino's
// check_for_privesc.py.
//
// Deliberately narrow, like the IAM-Vulnerable extractor: this reads ONE known file in
// ONE known shape. If that shape changes the method COUNT drops visibly, which is the
// failure we want — a benchmark that silently scores fewer cases looks like it improved.
func ParseRhinoCatalogue(src string) []GCPMethod {
	heads := gcpMethodRe.FindAllStringSubmatchIndex(src, -1)
	var out []GCPMethod
	for i, h := range heads {
		name := src[h[2]:h[3]]
		end := len(src)
		if i+1 < len(heads) {
			end = heads[i+1][0]
		}
		body := src[h[1]:end]
		pm := gcpPermsRe.FindStringSubmatch(body)
		if pm == nil {
			continue // a method with no permission list tells us nothing to test
		}
		var perms []string
		for _, q := range gcpQuoted.FindAllStringSubmatch(pm[1], -1) {
			if p := strings.TrimSpace(q[1]); p != "" {
				perms = append(perms, p)
			}
		}
		if len(perms) == 0 {
			continue
		}
		sort.Strings(perms)
		out = append(out, GCPMethod{Name: name, Permissions: perms})
	}
	return out
}

// ScoreGCPPrivesc grants exactly the permissions Rhino's catalogue names for each method
// and asks whether gcpiam detects an escalation.
//
// Grounded: the method NAME is the answer and is never fed to the detector — only the
// permissions are. A catalogue entry we detect for the wrong reason still counts as
// detected, which is why the report prints what fired.
func ScoreGCPPrivesc(path string) (GCPPrivescResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return GCPPrivescResult{}, fmt.Errorf("bench: read rhino catalogue: %w", err)
	}
	methods := ParseRhinoCatalogue(string(b))
	var res GCPPrivescResult
	for _, m := range methods {
		granted := make(map[string]bool, len(m.Permissions))
		for _, p := range m.Permissions {
			granted[strings.ToLower(p)] = true
		}
		can := func(p string) bool { return granted[strings.ToLower(p)] }
		for _, t := range gcpiam.DetectPrivesc(can) {
			m.Detected = append(m.Detected, t.Name)
		}
		m.Found = len(m.Detected) > 0
		res.Methods = append(res.Methods, m)
		res.Total++
		if m.Found {
			res.Hits++
		}
	}
	return res, nil
}

// RenderGCPPrivesc writes the per-method scorecard. Per-method for the same reason the
// AWS one is: some of Rhino's methods are not decidable from permissions alone, and an
// aggregate cannot tell a real gap from a principled refusal.
func RenderGCPPrivesc(r GCPPrivescResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== GCP privesc detection vs RhinoSecurityLabs catalogue — EXTERNAL answer key ===\n")
	fmt.Fprintf(&b, "methods scored: %d   detected: %d   recall: %.2f%%\n\n", r.Total, r.Hits, r.Recall()*100)
	fmt.Fprintf(&b, "| Method (Rhino's name = answer key) | Detected as | Permissions required |\n|---|---|---|\n")
	for _, m := range r.Methods {
		det := strings.Join(m.Detected, ", ")
		if det == "" {
			det = "— NOT DETECTED"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", m.Name, det, strings.Join(m.Permissions, " "))
	}
	if miss := r.Missed(); len(miss) > 0 {
		fmt.Fprintf(&b, "\nMISSED (%d):\n", len(miss))
		for _, m := range miss {
			fmt.Fprintf(&b, "  - %-34s [needs: %s]\n", m.Name, strings.Join(m.Permissions, " "))
		}
	}
	fmt.Fprintf(&b, "\nThe catalogue and its method names are Rhino Security Labs', not ours.\n")
	return b.String()
}

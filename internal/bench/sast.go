package bench

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// OWASP Benchmark v1.2 scoring — the neutral SAST leaderboard, the
// source-code counterpart to the WAVSEP DAST scorer. The Benchmark is a
// ~2,740-case BenchmarkJava tree; each case is one Java file that is either a
// real vulnerability (a SAST tool SHOULD flag it) or a safe look-alike (it
// must NOT), tagged with a category (sqli, xss, pathtraver, crypto, hash, …)
// and CWE. The metric is per-category Youden = TPR − FPR, exactly as WAVSEP.
//
// Scoring is SUT-agnostic: the ground truth lives in expectedresults*.csv
// (reused verbatim from the OWASP Benchmark project), and a case is matched
// by its file name (from the CSV) appearing in a finding's location — never
// by a hardcoded target string.

// sastCompetitors is the published OWASP-Benchmark SAST scorecard. Every SAST
// report cites it (CLAUDE.md §14.2.2). DAST tools on this corpus (e.g. ZAP
// ~13%) are NOT the comparison — only the SAST cohort (CLAUDE.md §6.1.1).
var sastCompetitors = Competitors{
	Leaderboard: "OWASP Benchmark v1.2 (SAST cohort)",
	Scores: map[string]string{
		"Veracode": "51%", "Checkmarx": "47%", "Fortify": "35%", "SonarQube": "6%",
	},
	Note: "Per-category Youden index (sensitivity + specificity − 1) across the BenchmarkJava test cases. SAST cohort only.",
}

// cweToOwaspCategory maps a finding's CWE to an OWASP-Benchmark category.
// Kept aligned with cweToWavsepCategory so the SAST and DAST benches agree on
// what "an sqli finding" means.
var cweToOwaspCategory = map[string]string{
	"CWE-89":  "sqli",
	"CWE-79":  "xss",
	"CWE-22":  "pathtraver",
	"CWE-78":  "cmdi",
	"CWE-90":  "ldapi",
	"CWE-643": "xpathi",
	"CWE-327": "crypto",
	"CWE-326": "crypto", // inadequate encryption strength (e.g. DES) — sibling of CWE-327; semgrep emits this for the OWASP-Benchmark crypto cases
	"CWE-328": "hash",
	"CWE-330": "weakrand",
	"CWE-501": "trustbound",
	"CWE-614": "securecookie",
}

// SastCase is one row of expectedresults.csv — the ground truth for one
// BenchmarkJava test case.
type SastCase struct {
	Name       string // test-file name, e.g. "BenchmarkTest00042"
	Category   string // sqli, xss, pathtraver, crypto, …
	Vulnerable bool   // true = real vuln (should flag); false = safe (must not)
}

// LoadSastCases reads expectedresults*.csv. Format:
// "<name>,<category>,<real-vulnerability>,<cwe>"; the "# test name,…" header
// (and any comment line) starts with '#' and is skipped.
func LoadSastCases(path string) ([]SastCase, error) {
	f, err := os.Open(path) //nolint:gosec // operator-provided ground-truth path
	if err != nil {
		return nil, fmt.Errorf("sast: open ground truth %s: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.Comment = '#' // the OWASP-Benchmark header line begins with '#'
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("sast: parse csv: %w", err)
	}
	var cases []SastCase
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		name := strings.TrimSpace(row[0])
		if name == "" {
			continue
		}
		cases = append(cases, SastCase{
			Name:       name,
			Category:   strings.ToLower(strings.TrimSpace(row[1])),
			Vulnerable: isTruthy(row[2]),
		})
	}
	return cases, nil
}

// SastCatScore is one category's confusion matrix + derived rates.
type SastCatScore struct {
	Category string `json:"category"`
	TP       int    `json:"tp"`
	FP       int    `json:"fp"`
	TN       int    `json:"tn"`
	FN       int    `json:"fn"`
}

func (c SastCatScore) tpr() float64 {
	if c.TP+c.FN == 0 {
		return 0
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}

func (c SastCatScore) fpr() float64 {
	if c.FP+c.TN == 0 {
		return 0
	}
	return float64(c.FP) / float64(c.FP+c.TN)
}

// Youden = sensitivity + specificity − 1 = TPR − FPR.
func (c SastCatScore) Youden() float64 { return c.tpr() - c.fpr() }

// SastReport is the per-category + overall scorecard.
type SastReport struct {
	PerCategory map[string]*SastCatScore `json:"per_category"`
	Overall     SastCatScore             `json:"overall"`
	Competitors Competitors              `json:"competitors"`
}

// ScoreSast scores a repository scan against the OWASP-Benchmark ground
// truth. A case is "flagged" iff some finding's location (Endpoint =
// "<file>:<line>") contains the case's file name AND the finding's CWE maps
// to the case's category — i.e. the scanner found the right bug class in the
// right file.
func ScoreSast(cases []SastCase, scan *types.Scan) *SastReport {
	flagged := map[string][]string{} // category → finding locations
	for _, f := range scan.FindingsRaw {
		cat := sastFindingCategory(f)
		if cat == "" {
			continue
		}
		flagged[cat] = append(flagged[cat], f.Endpoint)
	}

	rep := &SastReport{PerCategory: map[string]*SastCatScore{}, Competitors: sastCompetitors}
	for _, c := range cases {
		cs := rep.PerCategory[c.Category]
		if cs == nil {
			cs = &SastCatScore{Category: c.Category}
			rep.PerCategory[c.Category] = cs
		}
		hit := sastCaseFlagged(c, flagged[c.Category])
		switch {
		case c.Vulnerable && hit:
			cs.TP++
		case c.Vulnerable && !hit:
			cs.FN++
		case !c.Vulnerable && hit:
			cs.FP++
		default:
			cs.TN++
		}
	}
	for _, cs := range rep.PerCategory {
		rep.Overall.TP += cs.TP
		rep.Overall.FP += cs.FP
		rep.Overall.TN += cs.TN
		rep.Overall.FN += cs.FN
	}
	rep.Overall.Category = "OVERALL"
	return rep
}

func sastFindingCategory(f types.Finding) string {
	for _, cwe := range f.CWE {
		if cat, ok := cweToOwaspCategory[cwe]; ok {
			return cat
		}
	}
	return ""
}

// sastCaseFlagged reports whether any finding location names this case's file.
// Match on "<name>." so a 5-digit case id can't substring-collide with a
// longer one.
func sastCaseFlagged(c SastCase, locations []string) bool {
	needle := c.Name + "."
	for _, loc := range locations {
		if strings.Contains(loc, needle) {
			return true
		}
	}
	return false
}

// RenderSast formats the scorecard with the mandatory competitor cite.
func RenderSast(r *SastReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== OWASP Benchmark scorecard (repository SAST) ===\n")
	fmt.Fprintf(&b, "overall Youden:   %.2f%%  (TP=%d FP=%d TN=%d FN=%d)\n",
		r.Overall.Youden()*100, r.Overall.TP, r.Overall.FP, r.Overall.TN, r.Overall.FN)

	cats := make([]string, 0, len(r.PerCategory))
	for c := range r.PerCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	fmt.Fprintf(&b, "per-category:\n")
	for _, c := range cats {
		cs := r.PerCategory[c]
		fmt.Fprintf(&b, "  %-13s TP=%-4d FP=%-4d TN=%-4d FN=%-4d  Youden=%.2f%%\n",
			cs.Category, cs.TP, cs.FP, cs.TN, cs.FN, cs.Youden()*100)
	}
	b.WriteString(renderCompetitors(r.Competitors))
	return b.String()
}

// RunSast drives a full SAST benchmark: scan the source tree with the
// repository asset (semgrep/codeql fan out over the files), then score
// against the ground-truth CSV. target is the source dir (the operator
// extracts the BenchmarkJava tree from the image / clones it).
func RunSast(ctx context.Context, target, csvPath string, opts RunOptions) (*SastReport, error) {
	cases, err := LoadSastCases(csvPath)
	if err != nil {
		return nil, err
	}
	opts = opts.withDefaults()
	scan, err := runOnce(ctx, &Fixture{
		Name: "repo-owasp-benchmark", Asset: "repository", Target: target,
		Competitors: sastCompetitors,
	}, opts)
	if err != nil {
		return nil, fmt.Errorf("sast: scan: %w", err)
	}
	return ScoreSast(cases, scan), nil
}

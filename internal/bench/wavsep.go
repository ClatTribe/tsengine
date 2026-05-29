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

// WAVSEP scoring — the neutral DAST leaderboard (Shay Chen,
// sectoolmarket.com). WAVSEP is a deployed webapp of ~1,133 test cases;
// each is a distinct URL that is either a real vulnerability (should be
// flagged) or a false-positive case (must NOT be flagged), tagged with a
// category (sqli, xss, pathtraver, redirect, …). The metric is per-category
// Youden index = TPR − FPR.
//
// This is the DAST counterpart to the SAST OWASP-Benchmark scorer; the
// CWE→category map below is kept aligned with it. Scoring is SUT-agnostic
// (the guard test forbids WAVSEP target strings in this file) — the
// ground truth lives in expected-cases.csv, reused verbatim from the
// WAVSEP project.

// wavsepCompetitors is the published Shay Chen scorecard — every WAVSEP
// report cites it (CLAUDE.md §14.2.2).
var wavsepCompetitors = Competitors{
	Leaderboard: "Shay Chen WAVSEP comparison, sectoolmarket.com",
	Scores: map[string]string{
		"Acunetix": "87%", "Netsparker": "87%", "Burp-Active": "78%",
		"HP-WebInspect": "76%", "IBM-AppScan": "69%", "OWASP-ZAP": "56%",
	},
	Note: "Per-class Youden index (sensitivity + specificity − 1) across WAVSEP test cases.",
}

// cweToWavsepCategory maps a finding's CWE to a WAVSEP category. Aligned
// with the OWASP-Benchmark CWE→category math so the DAST and SAST benches
// agree on what "an sqli finding" means.
var cweToWavsepCategory = map[string]string{
	"CWE-89":  "sqli",
	"CWE-79":  "xss",
	"CWE-22":  "pathtraver",
	"CWE-98":  "pathtraver",
	"CWE-601": "redirect",
	"CWE-78":  "cmdi",
	"CWE-643": "xpathi",
	"CWE-90":  "ldapi",
}

// WavsepCase is one row of expected-cases.csv — the ground truth for one
// WAVSEP test case.
type WavsepCase struct {
	URL        string // identifying URL substring of the test case
	Category   string // sqli, xss, pathtraver, redirect, …
	Vulnerable bool   // true = real vuln (should flag); false = FP case (must not flag)
}

// LoadWavsepCases reads expected-cases.csv. Format: url,category,vulnerable
// (header row tolerated). vulnerable ∈ {true,false,1,0}.
func LoadWavsepCases(path string) ([]WavsepCase, error) {
	f, err := os.Open(path) //nolint:gosec // operator-provided ground-truth path
	if err != nil {
		return nil, fmt.Errorf("wavsep: open ground truth %s: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("wavsep: parse csv: %w", err)
	}
	var cases []WavsepCase
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		url := strings.TrimSpace(row[0])
		// Skip blanks, comment lines, and either header spelling ("url" or
		// the WAVSEP corpus's "url_path"). Real case paths start with "/",
		// so a "url"-prefixed first field is always a header, never data.
		if url == "" || strings.HasPrefix(url, "#") || strings.HasPrefix(strings.ToLower(url), "url") {
			continue
		}
		cases = append(cases, WavsepCase{
			URL:        url,
			Category:   strings.ToLower(strings.TrimSpace(row[1])),
			Vulnerable: isTruthy(row[2]),
		})
	}
	return cases, nil
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "y":
		return true
	}
	return false
}

// WavsepCatScore is one category's confusion matrix + derived rates.
type WavsepCatScore struct {
	Category string `json:"category"`
	TP       int    `json:"tp"`
	FP       int    `json:"fp"`
	TN       int    `json:"tn"`
	FN       int    `json:"fn"`
}

func (c WavsepCatScore) tpr() float64 {
	if c.TP+c.FN == 0 {
		return 0
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}
func (c WavsepCatScore) fpr() float64 {
	if c.FP+c.TN == 0 {
		return 0
	}
	return float64(c.FP) / float64(c.FP+c.TN)
}

// Youden = sensitivity + specificity − 1 = TPR − FPR.
func (c WavsepCatScore) Youden() float64 { return c.tpr() - c.fpr() }

// WavsepReport is the per-category + overall scorecard.
type WavsepReport struct {
	PerCategory map[string]*WavsepCatScore `json:"per_category"`
	Overall     WavsepCatScore             `json:"overall"`
	Competitors Competitors                `json:"competitors"`
}

// ScoreWavsep scores a scan against the WAVSEP ground truth. A test case
// is "flagged" iff some raw finding's endpoint contains the case URL AND
// the finding's CWE maps to the case's category — i.e. the scanner found
// the right class of bug at the right place.
func ScoreWavsep(cases []WavsepCase, scan *types.Scan) *WavsepReport {
	// (category → set of URL-substrings the scan flagged in that category)
	flagged := map[string][]string{}
	for _, f := range scan.FindingsRaw {
		cat := findingCategory(f)
		if cat == "" {
			continue
		}
		flagged[cat] = append(flagged[cat], f.Endpoint)
	}

	rep := &WavsepReport{PerCategory: map[string]*WavsepCatScore{}, Competitors: wavsepCompetitors}
	for _, c := range cases {
		cs := rep.PerCategory[c.Category]
		if cs == nil {
			cs = &WavsepCatScore{Category: c.Category}
			rep.PerCategory[c.Category] = cs
		}
		hit := caseFlagged(c, flagged[c.Category])
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

// findingCategory maps a finding to a WAVSEP category via the first CWE
// that has a mapping.
func findingCategory(f types.Finding) string {
	for _, cwe := range f.CWE {
		if cat, ok := cweToWavsepCategory[cwe]; ok {
			return cat
		}
	}
	return ""
}

func caseFlagged(c WavsepCase, endpoints []string) bool {
	for _, ep := range endpoints {
		if strings.Contains(ep, c.URL) {
			return true
		}
	}
	return false
}

// RenderWavsep formats the scorecard with the mandatory competitor cite.
func RenderWavsep(r *WavsepReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== WAVSEP scorecard (web_application DAST) ===\n")
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
		fmt.Fprintf(&b, "  %-12s TP=%-4d FP=%-3d TN=%-4d FN=%-4d  Youden=%.2f%%\n",
			cs.Category, cs.TP, cs.FP, cs.TN, cs.FN, cs.Youden()*100)
	}
	b.WriteString(renderCompetitors(r.Competitors))
	return b.String()
}

// RunWavsep drives a full WAVSEP run: scan the deployed WAVSEP root with
// the web_application asset (katana crawls the test-case URLs, the
// fan-out scans them), then score against the ground-truth CSV.
//
// Requires the WAVSEP webapp reachable at target and the sandbox image
// built with katana. The competitor scorecard is always available even
// when a run can't execute.
func RunWavsep(ctx context.Context, target, csvPath string, opts RunOptions) (*WavsepReport, error) {
	cases, err := LoadWavsepCases(csvPath)
	if err != nil {
		return nil, err
	}
	opts = opts.withDefaults()
	scan, err := runOnce(ctx, &Fixture{
		Name: "web-wavsep", Asset: "web_application", Target: target,
		Competitors: wavsepCompetitors,
	}, opts)
	if err != nil {
		return nil, fmt.Errorf("wavsep: scan: %w", err)
	}
	return ScoreWavsep(cases, scan), nil
}

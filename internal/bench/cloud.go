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

// CIS AWS Foundations Benchmark scoring — the cloud_account counterpart to
// the WAVSEP (DAST) and OWASP-Benchmark (SAST) scorers. There is NO neutral
// CSPM leaderboard (Prowler / Scout Suite / Wiz / Orca all self-publish), so
// the comparison is internal: CIS-control RECALL vs a mock AWS account seeded
// with a known-failing posture (CLAUDE.md §14). The headline metric is
// per-CIS-section recall = TP / (TP+FN) — of the controls the account
// violates, how many the engine flags — alongside a false-positive count
// (controls that hold but were flagged) so a "flag everything" scanner can't
// game recall.
//
// Scoring is SUT-agnostic: the ground truth (which CIS controls the seeded
// account violates, and the detector check_id for each) lives in
// expected-controls.csv, reused verbatim across runs of the same account. A
// control is "flagged" iff its check_id appears as a whole token in some
// finding's rule_id (e.g. prowler emits "prowler::<check_id>") — never via a
// hardcoded check string in this file.

// cloudCompetitors is the cloud_account scorecard cite. Every cloud report
// carries it (CLAUDE.md §14.2.2). No neutral CSPM leaderboard exists, so the
// reference is the CIS AWS Foundations recall against a seeded account.
var cloudCompetitors = Competitors{
	Leaderboard: "CIS AWS Foundations Benchmark (mock-account recall)",
	Note: "No neutral CSPM leaderboard — Prowler / Scout Suite / Wiz / Orca self-publish. " +
		"Reference is CIS-control recall vs. a mock AWS account seeded with a known-failing posture. " +
		"Honest-mapping discipline (CLAUDE.md §8): only seeded controls with a known detector are scored.",
}

// CloudCase is one row of expected-controls.csv — one CIS control, the CIS
// section it belongs to, the detector check_id that flags it, and whether the
// seeded mock account violates it.
type CloudCase struct {
	Control  string // CIS control id, e.g. "1.4"
	Section  string // iam, storage, logging, monitoring, networking
	CheckID  string // detector check_id, e.g. "iam_no_root_access_key"
	Violated bool   // true = account violates it (engine SHOULD flag); false = holds (must NOT flag)
}

// LoadCloudCases reads expected-controls.csv. Format:
// "<cis_control>,<section>,<check_id>,<violated>"; the header and any comment
// line begins with '#' and is skipped.
func LoadCloudCases(path string) ([]CloudCase, error) {
	f, err := os.Open(path) //nolint:gosec // operator-provided ground-truth path
	if err != nil {
		return nil, fmt.Errorf("cloud: open ground truth %s: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.Comment = '#'
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("cloud: parse csv: %w", err)
	}
	var cases []CloudCase
	for _, row := range rows {
		if len(row) < 4 {
			continue
		}
		control := strings.TrimSpace(row[0])
		checkID := strings.TrimSpace(row[2])
		if control == "" || checkID == "" {
			continue
		}
		cases = append(cases, CloudCase{
			Control:  control,
			Section:  strings.ToLower(strings.TrimSpace(row[1])),
			CheckID:  checkID,
			Violated: isTruthy(row[3]),
		})
	}
	return cases, nil
}

// CloudSectionScore is one CIS section's confusion matrix + derived rates.
type CloudSectionScore struct {
	Section string `json:"section"`
	TP      int    `json:"tp"`
	FP      int    `json:"fp"`
	TN      int    `json:"tn"`
	FN      int    `json:"fn"`
}

// Recall = TP / (TP+FN): of the controls the account violates, the fraction
// the engine flagged. This is the headline CIS metric (CLAUDE.md §14).
func (c CloudSectionScore) Recall() float64 {
	if c.TP+c.FN == 0 {
		return 1 // no violated controls in this section → trivially complete
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}

// Specificity = TN / (TN+FP): of the controls that hold, the fraction the
// engine correctly left unflagged. Surfaces a noisy "flag everything" engine.
func (c CloudSectionScore) Specificity() float64 {
	if c.TN+c.FP == 0 {
		return 1
	}
	return float64(c.TN) / float64(c.TN+c.FP)
}

// CloudReport is the per-section + overall scorecard.
type CloudReport struct {
	PerSection  map[string]*CloudSectionScore `json:"per_section"`
	Overall     CloudSectionScore             `json:"overall"`
	Competitors Competitors                   `json:"competitors"`
}

// ScoreCloud scores a cloud_account scan against the CIS ground truth. A
// control is "flagged" iff some finding's rule_id names its check_id as a
// whole token. Each ground-truth control is then bucketed by section into a
// TP/FP/TN/FN cell.
func ScoreCloud(cases []CloudCase, scan *types.Scan) *CloudReport {
	ruleIDs := make([]string, 0, len(scan.FindingsRaw))
	for _, f := range scan.FindingsRaw {
		ruleIDs = append(ruleIDs, f.RuleID)
	}

	rep := &CloudReport{PerSection: map[string]*CloudSectionScore{}, Competitors: cloudCompetitors}
	for _, c := range cases {
		ss := rep.PerSection[c.Section]
		if ss == nil {
			ss = &CloudSectionScore{Section: c.Section}
			rep.PerSection[c.Section] = ss
		}
		hit := cloudCaseFlagged(c, ruleIDs)
		switch {
		case c.Violated && hit:
			ss.TP++
		case c.Violated && !hit:
			ss.FN++
		case !c.Violated && hit:
			ss.FP++
		default:
			ss.TN++
		}
	}
	for _, ss := range rep.PerSection {
		rep.Overall.TP += ss.TP
		rep.Overall.FP += ss.FP
		rep.Overall.TN += ss.TN
		rep.Overall.FN += ss.FN
	}
	rep.Overall.Section = "OVERALL"
	return rep
}

// cloudCaseFlagged reports whether any finding's rule_id names this case's
// check_id as a whole token.
func cloudCaseFlagged(c CloudCase, ruleIDs []string) bool {
	for _, rid := range ruleIDs {
		if matchCheckID(rid, c.CheckID) {
			return true
		}
	}
	return false
}

// matchCheckID matches checkID inside ruleID as a whole token — the match
// must end at end-of-string or a non-identifier char, so a short check_id
// (s3_bucket_public_access) can't substring-collide with a longer one
// (s3_bucket_public_access_block).
func matchCheckID(ruleID, checkID string) bool {
	if checkID == "" {
		return false
	}
	from := 0
	for {
		idx := strings.Index(ruleID[from:], checkID)
		if idx < 0 {
			return false
		}
		end := from + idx + len(checkID)
		if end == len(ruleID) || !isCheckIDChar(ruleID[end]) {
			return true
		}
		from = from + idx + 1
	}
}

func isCheckIDChar(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// RenderCloud formats the scorecard with the mandatory competitor cite.
func RenderCloud(r *CloudReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== CIS AWS Foundations scorecard (cloud_account CSPM) ===\n")
	fmt.Fprintf(&b, "overall recall:   %.2f%%  (TP=%d FN=%d) · specificity %.2f%% (TN=%d FP=%d)\n",
		r.Overall.Recall()*100, r.Overall.TP, r.Overall.FN,
		r.Overall.Specificity()*100, r.Overall.TN, r.Overall.FP)

	sections := make([]string, 0, len(r.PerSection))
	for s := range r.PerSection {
		sections = append(sections, s)
	}
	sort.Strings(sections)
	fmt.Fprintf(&b, "per-section:\n")
	for _, s := range sections {
		ss := r.PerSection[s]
		fmt.Fprintf(&b, "  %-12s TP=%-3d FN=%-3d FP=%-3d TN=%-3d  recall=%.2f%%\n",
			ss.Section, ss.TP, ss.FN, ss.FP, ss.TN, ss.Recall()*100)
	}
	b.WriteString(renderCompetitors(r.Competitors))
	return b.String()
}

// RunCloud drives a full CIS benchmark: scan the cloud account with the
// posture engines (prowler + scoutsuite), then score against the ground-truth
// CSV. target is the provider ("aws" | "gcp" | "azure"); scoped, short-lived
// credentials are forwarded from the environment by the scan CLI — never
// written to disk or to vulnerabilities.json.
func RunCloud(ctx context.Context, target, csvPath string, opts RunOptions) (*CloudReport, error) {
	cases, err := LoadCloudCases(csvPath)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(target) == "" {
		target = "aws"
	}
	opts = opts.withDefaults()
	scan, err := runOnce(ctx, &Fixture{
		Name: "cloud-cis-baseline", Asset: "cloud_account", Target: target,
		Competitors: cloudCompetitors,
	}, opts)
	if err != nil {
		return nil, fmt.Errorf("cloud: scan: %w", err)
	}
	return ScoreCloud(cases, scan), nil
}

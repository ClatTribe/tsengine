// Package accuracybench runs every deterministic SMB-parity core's labeled accuracy corpus and
// renders one unified scorecard — the capstone of the "measure the accuracy" work. Each core ships
// its own corpus + scorer (e.g. identitythreat.ScoreCorpus over identitythreat.Corpus); this
// aggregates them so the whole campaign's FP/FN accuracy is a single runnable, CI-gateable report.
//
// It measures the host-side deterministic cores (LLM-free, no sandbox); the sandbox-run OSS-tool
// asset benches (WAVSEP, OWASP Benchmark, …) live under bench/ and need deployed targets.
package accuracybench

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/apiauthz"
	"github.com/ClatTribe/tsengine/internal/identitythreat"
	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/registrywatch"
	"github.com/ClatTribe/tsengine/internal/shadowit"
	"github.com/ClatTribe/tsengine/internal/webauth"
)

// CoreScore is one core's measured accuracy over its labeled corpus.
type CoreScore struct {
	Core      string  `json:"core"`
	Asset     string  `json:"asset"`
	Recall    float64 `json:"recall"`
	Precision float64 `json:"precision"`
	Cases     int     `json:"cases"`
}

// Perfect reports whether the core hit recall=1.0 AND precision=1.0 (the gate).
func (c CoreScore) Perfect() bool { return c.Recall == 1.0 && c.Precision == 1.0 }

// Run executes every core's built-in labeled accuracy corpus and returns the per-core scores,
// sorted by core name (deterministic).
func Run() []CoreScore {
	clock := func(min int) time.Time {
		return time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute)
	}

	itdr := identitythreat.ScoreCorpus(identitythreat.Corpus(clock), identitythreat.Config{})
	scopes := shadowit.ScoreScopes(shadowit.ScopeCorpus())
	email := operate.ScoreDomains(operate.EmailAuthCorpus())
	wall := webauth.ScoreLoginWall(webauth.LoginWallCorpus(), webauth.LoginFlow{})
	tags := registrywatch.ScoreTags(registrywatch.TagCorpus())
	authz := apiauthz.ScoreAuthz(apiauthz.AuthzCorpus())

	out := []CoreScore{
		{"identitythreat (ITDR rules)", "identity", itdr.Recall(), itdr.Precision(), itdr.Cases},
		{"shadowit (sensitive-scope)", "saas_posture", scopes.Recall(), scopes.Precision(), scopes.TP + scopes.FP + scopes.FN + scopes.TN},
		{"operate (email-auth)", "identity/domain", email.Recall(), email.Precision(), email.Cases},
		{"webauth (login-wall)", "web_application", wall.Recall(), wall.Precision(), wall.TP + wall.FP + wall.FN + wall.TN},
		{"registrywatch (mutable-tag)", "container_image", tags.Recall(), tags.Precision(), tags.TP + tags.FP + tags.FN + tags.TN},
		{"apiauthz (BOLA/BFLA/mass-assign)", "api", authz.Recall(), authz.Precision(), authz.TP + authz.FP + authz.FN + authz.TN},
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Core < out[j].Core })
	return out
}

// Render formats the scores as a fixed-width scorecard table.
func Render(scores []CoreScore) string {
	var b strings.Builder
	b.WriteString("tsengine detection-accuracy scorecard (deterministic cores)\n")
	b.WriteString(fmt.Sprintf("%-34s %-16s %7s %9s %6s  %s\n", "CORE", "ASSET", "RECALL", "PRECISION", "CASES", "GATE"))
	b.WriteString(strings.Repeat("-", 92) + "\n")
	totalCases, allPerfect := 0, true
	for _, s := range scores {
		totalCases += s.Cases
		gate := "PASS"
		if !s.Perfect() {
			gate = "FAIL"
			allPerfect = false
		}
		b.WriteString(fmt.Sprintf("%-34s %-16s %6.2f %8.2f %6d  %s\n", s.Core, s.Asset, s.Recall, s.Precision, s.Cases, gate))
	}
	b.WriteString(strings.Repeat("-", 92) + "\n")
	verdict := "ALL CORES PASS"
	if !allPerfect {
		verdict = "REGRESSION — a core fell below recall=1.0 / precision=1.0"
	}
	b.WriteString(fmt.Sprintf("%d cores, %d labeled cases — %s\n", len(scores), totalCases, verdict))
	return b.String()
}

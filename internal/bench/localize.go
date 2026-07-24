package bench

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/codelocalize"
)

// localize.go is the Vulnerability-LOCALIZATION benchmark — the measured-efficacy yardstick for the
// codelocalize substrate (the G1 code-depth capability). Its lineage is Cisco's Antares
// Vulnerability-Localization Benchmark: score whether, GIVEN a CWE class, the engine navigates an
// unfamiliar repo to the file that actually holds the sink. This is a distinct axis from the per-asset
// DETECTION recall benches (§14) — detection asks "did we find a bug?", localization asks "did we point
// at the right file?", which is where the real triage cost (and Antares' whole pitch) lives.
//
// Metrics per scenario: recall@{1,3,5} (fraction of ground-truth sink files in the top-k) and MRR
// (1/rank of the first truth hit). Ablation is built in: run the same scenarios with the LLM-free
// HeuristicLocalizer vs the LLMLocalizer and the delta is the model's measured localization lift
// (substrate-vs-agent, §14.2). Fixtures are synthetic + planted (ground truth is exact), so no live
// target is needed — the number runs on a laptop/CI with no key.

// LocalizeScenario is one planted repo with a known-answer sink location.
type LocalizeScenario struct {
	Name  string
	Query codelocalize.Query
	Repo  codelocalize.Repo
	Truth []string // repo-relative paths that actually contain the sink (ground truth)
}

// LocalizeScore is one scenario's result.
type LocalizeScore struct {
	Name      string
	Engine    string
	RecallAt1 float64
	RecallAt3 float64
	RecallAt5 float64
	MRR       float64
	Found     int // truth files that appeared anywhere in the ranking
	Total     int // len(Truth)
}

// ScoreLocalize scores a localization result against ground truth. Pure — depends only on ranked paths
// vs the truth set, never on fixture internals (so scoring cannot overfit to a specific fixture).
func ScoreLocalize(sc LocalizeScenario, res codelocalize.Result) LocalizeScore {
	rankOf := map[string]int{}
	for i, c := range res.Ranked {
		if _, seen := rankOf[c.Path]; !seen {
			rankOf[c.Path] = i + 1
		}
	}
	total := len(sc.Truth)
	recallAt := func(k int) float64 {
		if total == 0 {
			return 0
		}
		hit := 0
		for _, p := range sc.Truth {
			if r, ok := rankOf[p]; ok && r <= k {
				hit++
			}
		}
		return float64(hit) / float64(total)
	}
	best, found := 0, 0
	for _, p := range sc.Truth {
		if r, ok := rankOf[p]; ok {
			found++
			if best == 0 || r < best {
				best = r
			}
		}
	}
	mrr := 0.0
	if best > 0 {
		mrr = 1.0 / float64(best)
	}
	return LocalizeScore{
		Name: sc.Name, Engine: res.Engine,
		RecallAt1: recallAt(1), RecallAt3: recallAt(3), RecallAt5: recallAt(5),
		MRR: mrr, Found: found, Total: total,
	}
}

// RunLocalize scores every scenario with the given localizer.
func RunLocalize(ctx context.Context, loc codelocalize.Localizer, scenarios []LocalizeScenario) ([]LocalizeScore, error) {
	var out []LocalizeScore
	for _, sc := range scenarios {
		res, err := loc.Localize(ctx, sc.Query, sc.Repo)
		if err != nil {
			return nil, fmt.Errorf("scenario %q: %w", sc.Name, err)
		}
		out = append(out, ScoreLocalize(sc, res))
	}
	return out, nil
}

// AggregateLocalize returns the mean recall@k and MRR across scores.
func AggregateLocalize(scores []LocalizeScore) LocalizeScore {
	agg := LocalizeScore{Name: "AGGREGATE"}
	if len(scores) == 0 {
		return agg
	}
	for _, s := range scores {
		agg.RecallAt1 += s.RecallAt1
		agg.RecallAt3 += s.RecallAt3
		agg.RecallAt5 += s.RecallAt5
		agg.MRR += s.MRR
		agg.Found += s.Found
		agg.Total += s.Total
	}
	n := float64(len(scores))
	agg.RecallAt1 /= n
	agg.RecallAt3 /= n
	agg.RecallAt5 /= n
	agg.MRR /= n
	if len(scores) > 0 {
		agg.Engine = scores[0].Engine
	}
	return agg
}

// RenderLocalize renders the scorecard. The Antares citation is MANDATORY (anti-overfit §14.2 #2): a
// localization bench must name the external reference it measures against.
func RenderLocalize(scores []LocalizeScore) string {
	var b strings.Builder
	b.WriteString("# Vulnerability-Localization Benchmark\n")
	b.WriteString("Reference: Cisco Antares Vulnerability-Localization Benchmark (open-weight 350M/1B SLMs).\n\n")
	b.WriteString("| Scenario | Engine | recall@1 | recall@3 | recall@5 | MRR | found |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, s := range scores {
		fmt.Fprintf(&b, "| %s | %s | %.2f | %.2f | %.2f | %.2f | %d/%d |\n",
			s.Name, s.Engine, s.RecallAt1, s.RecallAt3, s.RecallAt5, s.MRR, s.Found, s.Total)
	}
	agg := AggregateLocalize(scores)
	fmt.Fprintf(&b, "| **%s** | %s | **%.2f** | **%.2f** | **%.2f** | **%.2f** | %d/%d |\n",
		agg.Name, agg.Engine, agg.RecallAt1, agg.RecallAt3, agg.RecallAt5, agg.MRR, agg.Found, agg.Total)
	return b.String()
}

// RenderLocalizeAblation renders the substrate-vs-agent lift (§14.2 #4).
func RenderLocalizeAblation(base, agent []LocalizeScore) string {
	b := AggregateLocalize(base)
	a := AggregateLocalize(agent)
	var sb strings.Builder
	sb.WriteString("## Ablation — LLM localization lift (substrate → agent)\n")
	fmt.Fprintf(&sb, "recall@1: %.2f → %.2f (Δ %+.2f)\n", b.RecallAt1, a.RecallAt1, a.RecallAt1-b.RecallAt1)
	fmt.Fprintf(&sb, "recall@3: %.2f → %.2f (Δ %+.2f)\n", b.RecallAt3, a.RecallAt3, a.RecallAt3-b.RecallAt3)
	fmt.Fprintf(&sb, "MRR:      %.2f → %.2f (Δ %+.2f)\n", b.MRR, a.MRR, a.MRR-b.MRR)
	return sb.String()
}

// LocalizeScenarios is the built-in synthetic corpus: one planted sink per scenario across the common
// first-party CWE classes, each with incidental/clean decoys so a naive "everything is a sink" ranker
// scores poorly. Ground truth is exact. Extend by appending — the scoring is fixture-agnostic.
func LocalizeScenarios() []LocalizeScenario {
	clean := func(path string) codelocalize.File {
		return codelocalize.File{Path: path, Content: "package x\nfunc helper(a, b int) int { return a + b }\n// pure utility, no I/O\n"}
	}
	scs := []LocalizeScenario{
		{
			Name:  "sqli-string-concat",
			Query: codelocalize.Query{CWE: []string{"CWE-89"}, Title: "SQL injection in user lookup"},
			Repo: codelocalize.Repo{
				clean("internal/util/math.go"),
				clean("internal/util/str.go"),
				{Path: "internal/store/users.go", Content: "func Find(db *sql.DB, r *http.Request) {\n name := r.URL.Query().Get(\"name\")\n db.Query(\"SELECT * FROM users WHERE name='\" + name + \"'\")\n}"},
				{Path: "internal/store/config.go", Content: "// static config, no user input\nconst dsn = \"postgres://localhost\"\n"},
			},
			Truth: []string{"internal/store/users.go"},
		},
		{
			Name:  "xss-reflected",
			Query: codelocalize.Query{CWE: []string{"CWE-79"}, Title: "Reflected XSS in search results"},
			Repo: codelocalize.Repo{
				clean("web/format.js"),
				{Path: "web/search.js", Content: "function render(req, res) {\n const q = req.query.q;\n res.send('<h1>Results for ' + q + '</h1>');\n}"},
				{Path: "web/static.js", Content: "export const NAV = ['home','about'];\n"},
			},
			Truth: []string{"web/search.js"},
		},
		{
			Name:  "command-injection",
			Query: codelocalize.Query{CWE: []string{"CWE-78"}, Title: "OS command injection in ping tool"},
			Repo: codelocalize.Repo{
				clean("cmd/util.go"),
				{Path: "cmd/ping.go", Content: "func ping(r *http.Request) {\n host := r.FormValue(\"host\")\n exec.Command(\"sh\", \"-c\", \"ping -c1 \"+host).Run()\n}"},
				{Path: "cmd/version.go", Content: "const Version = \"1.2.3\"\n"},
			},
			Truth: []string{"cmd/ping.go"},
		},
		{
			Name:  "path-traversal",
			Query: codelocalize.Query{CWE: []string{"CWE-22"}, Title: "Path traversal in file download"},
			Repo: codelocalize.Repo{
				clean("srv/health.go"),
				{Path: "srv/download.go", Content: "func dl(w http.ResponseWriter, r *http.Request) {\n name := r.URL.Query().Get(\"f\")\n b, _ := os.ReadFile(filepath.Join(\"/data\", name))\n w.Write(b)\n}"},
				{Path: "srv/index.go", Content: "func home(w http.ResponseWriter) { w.Write([]byte(\"ok\")) }\n"},
			},
			Truth: []string{"srv/download.go"},
		},
		{
			Name:  "deserialization",
			Query: codelocalize.Query{CWE: []string{"CWE-502"}, Title: "Insecure deserialization of session"},
			Repo: codelocalize.Repo{
				clean("app/helpers.py"),
				{Path: "app/session.py", Content: "def load(request):\n data = request.cookies.get('s')\n return pickle.loads(base64.b64decode(data))\n"},
				{Path: "app/consts.py", Content: "MAX_AGE = 3600\n"},
			},
			Truth: []string{"app/session.py"},
		},
		{
			Name:  "ssrf-fetch",
			Query: codelocalize.Query{CWE: []string{"CWE-918"}, Title: "SSRF via webhook URL"},
			Repo: codelocalize.Repo{
				clean("svc/util.py"),
				{Path: "svc/webhook.py", Content: "def call(request):\n url = request.form['callback_url']\n return requests.get(url).text\n"},
				{Path: "svc/models.py", Content: "class User:\n  name = ''\n"},
			},
			Truth: []string{"svc/webhook.py"},
		},
	}
	// deterministic order (§10 reproducibility).
	sort.Slice(scs, func(i, j int) bool { return scs[i].Name < scs[j].Name })
	return scs
}

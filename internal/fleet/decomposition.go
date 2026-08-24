package fleet

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/webagent"
)

// decomposition.go builds the engagement FRONTIER (ADR 0030 D4): the authorized surface split into
// ordered, capped chunks a worker runs over. Two ADR invariants live here:
//
//   - D4 "the frontier is intelligence-led, ORDERING IS THE BOUND": chunks are scored by real
//     evidence (auth → L1 seeds ranked by L1.5 enrichment → CVE probes → crown-jewel routes →
//     residual), so the highest-evidence work completes before any cap cuts the tail.
//   - D5 vector 1 (discovery loop): residual discovered routes pass shape-dedup + hard caps, and
//     OVERFLOW IS COUNTED AND DISCLOSED — never silently dropped, never explored (§5.2 rule 5).
//
// Deterministic: identical input yields an identical ordered plan (zero token cost, golden-testable).

// Tier bands. Higher tier = earlier in the plan. The base scores are spaced so a tier never loses to
// a lower one on within-tier signal alone — the ordering IS the bound.
const (
	tierAuth     = 5 // auth establishment (wave 0)
	tierSeed     = 4 // L1 scanner seeds
	tierCVEProbe = 3 // corpus-driven CVE probes (threatinformed)
	tierCrown    = 2 // crown-jewel routes (EstateLead)
	tierResidual = 1 // discovered surface, capped
)

var tierBase = map[int]int{tierAuth: 5_000_000, tierSeed: 4_000_000, tierCVEProbe: 3_000_000, tierCrown: 2_000_000, tierResidual: 1_000_000}

// Caps bound the frontier (D5). Zero uses the env default, then a hard fallback.
type Caps struct {
	MaxChunks int
	MaxRoutes int
}

func (c Caps) norm() Caps {
	if c.MaxChunks <= 0 {
		c.MaxChunks = envInt("TSENGINE_FLEET_MAX_CHUNKS", 50)
	}
	if c.MaxRoutes <= 0 {
		c.MaxRoutes = envInt("TSENGINE_FLEET_MAX_ROUTES", 200)
	}
	return c
}

// FrontierInput is everything the coordinator knows about the authorized surface at plan time. Scope
// is LOCKED here: the worker never adds a route to the allowlist mid-run (ADR D2) — new discoveries
// re-enter as a later FrontierInput, never as live scope expansion.
type FrontierInput struct {
	Target     string
	Auth       bool                   // an auth recipe is available → an auth chunk runs first (wave 0)
	Seeds      []webagent.SeedFinding // Tier 1 (L1 scanner findings to confirm)
	CVEProbes  []CVEProbe             // Tier 2 (threatinformed CVE probes over observed tech)
	Leads      []webagent.EstateLead  // Tier 3 (crown-jewel routes)
	Discovered []string               // Tier 4 residual (raw URLs)
	Caps       Caps
}

// CVEProbe is one corpus-driven probe (a Tier-2 chunk): a route and the CVE/template it targets, with
// the intel rank that ordered it (KEV/EPSS/exploit — threatinformed.Plan's own ordering).
type CVEProbe struct {
	Route    string
	Class    string // e.g. "cve" or the nuclei template id
	Rank     int    // higher = stronger intel (KEV > EPSS > pub-exploit); from the plan
	Evidence string // why (the intel that grounds it)
}

// Chunk is one scoped slice of the surface for a single worker. Declares (Class × Routes) so a
// completed chunk with no finding grounds a Clean (Phase B): we know what was ATTEMPTED.
type Chunk struct {
	ID      string   `json:"id"`
	Tier    int      `json:"tier"`
	Score   int      `json:"score"`
	Reason  string   `json:"reason"`
	Class   string   `json:"class,omitempty"` // the class this chunk attempts (seeds/cve); "" = general
	Routes  []string `json:"routes"`          // raw URLs the worker probes
	AuthCtx string   `json:"auth_ctx,omitempty"`
	// StateKey names shared/reset state this chunk's differentials depend on (e.g. a coupon
	// re-armed between race phases). Chunks sharing one never run in the same wave — concurrent
	// probes would corrupt each other's controls (ADR 0030 Phase C, §5.1 rule 4 ported).
	StateKey string                 `json:"state_key,omitempty"`
	Seeds    []webagent.SeedFinding `json:"-"` // the seeds this chunk confirms (fed to the worker)
}

// DecomposeResult is the ordered plan plus the honest overflow disclosure (D5 vector 1).
type DecomposeResult struct {
	Chunks        []Chunk `json:"chunks"`
	DroppedRoutes int     `json:"dropped_routes"`
	DroppedChunks int     `json:"dropped_chunks"`
	Disclosure    string  `json:"disclosure,omitempty"` // rendered when anything was capped
}

// Decompose turns the frontier into an ordered, capped, deduped chunk plan. Deterministic.
func Decompose(in FrontierInput) DecomposeResult {
	caps := in.Caps.norm()
	var chunks []Chunk
	n := 0
	id := func() string { n++; return fmt.Sprintf("chunk-%04d", n) }

	// Tier 0 — auth establishment, one chunk, top priority (wave 0).
	if in.Auth {
		chunks = append(chunks, Chunk{
			ID: id(), Tier: tierAuth, Score: tierBase[tierAuth],
			Reason: "establish + validate the authenticated session (wave 0; recipe reused by later chunks)",
			Routes: []string{in.Target}, AuthCtx: "primary",
		})
	}

	// Tier 1 — one chunk per L1 seed, ranked by L1.5 enrichment then severity (the L15Summary order).
	for _, s := range in.Seeds {
		if s.Route == "" {
			continue
		}
		chunks = append(chunks, Chunk{
			ID: id(), Tier: tierSeed,
			Score:  tierBase[tierSeed] + enrichmentWeight(s.Enrichment) + severityWeight(s.Severity),
			Reason: fmt.Sprintf("confirm L1 %s seed on %s (%s)", orQ(s.Class, "finding"), s.Route, provenance(s)),
			Class:  s.Class, Routes: []string{s.Route}, Seeds: []webagent.SeedFinding{s},
		})
	}

	// Tier 2 — corpus CVE probes, ranked by intel strength.
	for _, p := range in.CVEProbes {
		if p.Route == "" {
			continue
		}
		chunks = append(chunks, Chunk{
			ID: id(), Tier: tierCVEProbe, Score: tierBase[tierCVEProbe] + clampRank(p.Rank),
			Reason: fmt.Sprintf("threat-intel probe %s on %s (%s)", orQ(p.Class, "cve"), p.Route, orQ(p.Evidence, "corpus match")),
			Class:  p.Class, Routes: []string{p.Route},
		})
	}

	// Tier 3 — crown-jewel routes (a route that provably reaches something valuable).
	for _, l := range in.Leads {
		if l.Route == "" {
			continue
		}
		chunks = append(chunks, Chunk{
			ID: id(), Tier: tierCrown, Score: tierBase[tierCrown] + crownWeight(l),
			Reason: fmt.Sprintf("crown-jewel route %s → reaches %s", l.Route, orQ(l.Reaches, "a crown jewel")),
			Routes: []string{l.Route},
		})
	}

	// Tier 4 — residual discovered surface: shape-dedup, param-bearing first, static dropped, hard cap.
	residual, droppedRoutes := residualRoutes(in.Discovered, caps.MaxRoutes)
	for _, r := range residual {
		chunks = append(chunks, Chunk{
			ID: id(), Tier: tierResidual, Score: tierBase[tierResidual] + paramWeight(r),
			Reason: "residual discovered route", Routes: []string{r},
		})
	}

	// Stable sort by score desc (ties keep insertion order → deterministic; id already encodes it).
	sort.SliceStable(chunks, func(i, j int) bool { return chunks[i].Score > chunks[j].Score })

	// Chunk cap: the ordering above put the highest-evidence work first, so a cap cuts the tail.
	droppedChunks := 0
	if len(chunks) > caps.MaxChunks {
		droppedChunks = len(chunks) - caps.MaxChunks
		chunks = chunks[:caps.MaxChunks]
	}

	res := DecomposeResult{Chunks: chunks, DroppedRoutes: droppedRoutes, DroppedChunks: droppedChunks}
	if droppedRoutes > 0 || droppedChunks > 0 {
		res.Disclosure = fmt.Sprintf(
			"frontier capped: %d discovered route(s) and %d lower-priority chunk(s) were NOT explored "+
				"(over MAX_ROUTES=%d / MAX_CHUNKS=%d). They are disclosed, never silently dropped — re-run "+
				"with higher caps or a narrower scope to reach them.",
			droppedRoutes, droppedChunks, caps.MaxRoutes, caps.MaxChunks)
	}
	return res
}

// --- ranking helpers (deterministic) ---

// enrichmentWeight scores an L15Summary string by the same order the digest ranks by: KEV/ransomware
// dominates, then a weaponized module, then a public exploit, then network-attackable, then automatable.
func enrichmentWeight(enr string) int {
	e := strings.ToLower(enr)
	w := 0
	if strings.Contains(e, "kev") || strings.Contains(e, "ransomware") {
		w += 1000
	}
	if strings.Contains(e, "weaponized") {
		w += 500
	}
	if strings.Contains(e, "pub-exploit") {
		w += 200
	}
	if strings.Contains(e, "av:network") {
		w += 100
	}
	if strings.Contains(e, "ssvc-automatable:yes") {
		w += 150
	}
	return w
}

func severityWeight(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 40
	case "high":
		return 30
	case "medium":
		return 20
	case "low":
		return 10
	}
	return 0
}

func crownWeight(l webagent.EstateLead) int {
	w := 10 // a lead exists at all
	if len(l.Evidence) > 0 {
		w += 20 // graph-proven path, not asserted
	}
	return w
}

func clampRank(r int) int {
	if r < 0 {
		return 0
	}
	if r > 900_000 {
		return 900_000
	}
	return r
}

func paramWeight(rawURL string) int {
	if strings.Contains(rawURL, "?") && strings.Contains(rawURL, "=") {
		return 100 // param-bearing routes are the injectable surface — probe them before static
	}
	return 0
}

// --- residual filtration (D5 vector 1 counter) ---

var numSeg = regexp.MustCompile(`^\d+$`)

// residualRoutes shape-dedups discovered routes (/items/1 ≡ /items/N), drops static assets, keeps
// param-bearing first, and caps the count — returning the kept set and the DROPPED count for
// disclosure. A route beyond the cap is counted, never silently discarded (§5.2 rule 5).
func residualRoutes(discovered []string, maxRoutes int) (kept []string, dropped int) {
	seenShape := map[string]bool{}
	var candidates []string
	for _, raw := range discovered {
		if raw == "" || isStaticAsset(raw) {
			continue
		}
		shape := urlShape(raw)
		if seenShape[shape] {
			continue // a different index of a route already represented — one probe covers the shape
		}
		seenShape[shape] = true
		candidates = append(candidates, raw)
	}
	// Deterministic order: param-bearing first, then lexicographic.
	sort.SliceStable(candidates, func(i, j int) bool {
		pi, pj := paramWeight(candidates[i]), paramWeight(candidates[j])
		if pi != pj {
			return pi > pj
		}
		return candidates[i] < candidates[j]
	})
	if len(candidates) > maxRoutes {
		dropped = len(candidates) - maxRoutes
		candidates = candidates[:maxRoutes]
	}
	return candidates, dropped
}

func isStaticAsset(raw string) bool {
	u, err := url.Parse(raw)
	p := raw
	if err == nil {
		p = u.Path
	}
	p = strings.ToLower(p)
	for _, ext := range []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// urlShape normalizes numeric path segments to a placeholder so /items/1 and /items/2 collapse; query
// keys are kept but values dropped (a param's presence is the surface, its value is not).
func urlShape(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	var segs []string
	for _, s := range strings.Split(u.Path, "/") {
		if numSeg.MatchString(s) || (len(s) >= 8 && isHexish(s)) {
			segs = append(segs, "{id}")
		} else {
			segs = append(segs, s)
		}
	}
	keys := make([]string, 0)
	for k := range u.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return u.Host + strings.Join(segs, "/") + "?" + strings.Join(keys, "&")
}

func isHexish(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF-", r) {
			return false
		}
	}
	return true
}

// --- small utils ---

func provenance(s webagent.SeedFinding) string {
	if s.Tool != "" {
		return s.Tool
	}
	return "L1"
}

func orQ(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

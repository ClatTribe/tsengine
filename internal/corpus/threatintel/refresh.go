package threatintel

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// RefreshOptions configures an out-of-band corpus refresh.
type RefreshOptions struct {
	OutDir        string       // output dir (default "./corpus")
	HTTPClient    *http.Client // default: 120s timeout
	KEVURL        string       // override for tests
	EPSSURL       string       // override for tests
	ExploitDBURL  string       // override for tests; best-effort (a fetch failure doesn't fail the refresh)
	MetasploitURL string       // override for tests; best-effort (a fetch failure doesn't fail the refresh)
	NucleiURL     string       // override for tests; best-effort — the "can we test for this CVE" index
	// VulnrichmentURL enables CISA's SSVC decision points (vulnrichment.go). OPT-IN because the
	// archive is large; absent, the corpus carries no SSVC and says so by its absence rather than
	// by a default.
	VulnrichmentURL string
	// ExploitIntelURL is the OPT-IN offensive-face source (ADR 0019): the nuclei-templates archive whose
	// template BODIES become the exploit_intel.json sidecar. Only fetched when set (the archive is large),
	// best-effort like ExploitDB — a failure never blocks the KEV+EPSS refresh; the sidecar is just skipped.
	ExploitIntelURL string
	NVDURL          string // OPT-IN CVSS-vector source: only fetched when set. NVD is large + paginated, so
	//             it's wired to a bulk mirror / paging fetcher (a single GET to the live API returns one page),
	//             never defaulted on. Best-effort like ExploitDB (a fetch failure doesn't fail the refresh).
}

func (o RefreshOptions) withDefaults() RefreshOptions {
	if o.OutDir == "" {
		o.OutDir = "./corpus"
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 120 * time.Second}
	}
	if o.KEVURL == "" {
		o.KEVURL = KEVURL
	}
	if o.EPSSURL == "" {
		o.EPSSURL = EPSSURL
	}
	if o.ExploitDBURL == "" {
		o.ExploitDBURL = ExploitDBURL
	}
	if o.MetasploitURL == "" {
		o.MetasploitURL = MetasploitURL
	}
	if o.NucleiURL == "" {
		o.NucleiURL = NucleiTemplatesURL
	}
	return o
}

// Refresh fetches the CISA KEV + FIRST.org EPSS feeds, merges them into the
// pinned corpus, and writes <OutDir>/threat_intel.json + sidecar manifest.
// This is the L0 cron-refresh step (CLAUDE.md §5) — run out of band, NOT per
// scan. Returns the manifest and the data-file path.
func Refresh(ctx context.Context, opts RefreshOptions) (Manifest, string, error) {
	opts = opts.withDefaults()

	kevBody, err := httpGet(ctx, opts.HTTPClient, opts.KEVURL)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("threatintel: fetch KEV: %w", err)
	}
	kev, kevAsOf, kevVer, err := ParseKEV(kevBody)
	_ = kevBody.Close()
	if err != nil {
		return Manifest{}, "", err
	}

	epssBody, err := httpGet(ctx, opts.HTTPClient, opts.EPSSURL)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("threatintel: fetch EPSS: %w", err)
	}
	epss, epssAsOf, err := ParseEPSSGzip(epssBody)
	_ = epssBody.Close()
	if err != nil {
		return Manifest{}, "", err
	}

	// ExploitDB is best-effort: it's a large optional overlay (public-exploit-exists), so a fetch or
	// parse failure must NOT block the KEV+EPSS refresh — we just build the corpus without it.
	var exploits map[string][]string
	if body, ferr := httpGet(ctx, opts.HTTPClient, opts.ExploitDBURL); ferr == nil {
		exploits, _ = ParseExploitDB(body)
		_ = body.Close()
	}

	// Metasploit is best-effort for the same reason as ExploitDB: it is a large optional overlay, and
	// losing the WEAPONIZED rung must never cost the KEV+EPSS refresh that everything else depends on.
	var weaponized map[string][]string
	var weaponRank map[string]int
	if body, ferr := httpGet(ctx, opts.HTTPClient, opts.MetasploitURL); ferr == nil {
		weaponized, weaponRank, _ = ParseMetasploitRanked(body)
		_ = body.Close()
	}

	// Nuclei template availability, best-effort for the same reason as the others. Losing it
	// degrades the probe plan to today's assume-every-CVE-is-testable behaviour rather than
	// failing the refresh — and the plan reports the degradation rather than hiding it.
	var templates map[string]string
	if body, ferr := httpGet(ctx, opts.HTTPClient, opts.NucleiURL); ferr == nil {
		templates, _ = ParseNucleiTemplates(body)
		_ = body.Close()
	}

	// CISA Vulnrichment (SSVC) is OPT-IN + best-effort, like NVD: the archive is large (~300k files),
	// so it is fetched only when a URL is configured, and a failure never blocks the KEV+EPSS
	// refresh. Without it the corpus simply carries no SSVC — the other six feeds are unaffected,
	// and nothing reports an assessment CISA did not make.
	var ssvc map[string]*types.SSVC
	if opts.VulnrichmentURL != "" {
		if body, ferr := httpGet(ctx, opts.HTTPClient, opts.VulnrichmentURL); ferr == nil {
			ssvc, _ = ParseVulnrichment(body)
			_ = body.Close()
		}
	}

	// NVD CVSS vectors are OPT-IN + best-effort: only fetched when a URL is configured (a bulk mirror / pager),
	// and a failure never blocks the KEV+EPSS refresh.
	var cvss map[string]NVDEntry
	if opts.NVDURL != "" {
		if body, ferr := httpGet(ctx, opts.HTTPClient, opts.NVDURL); ferr == nil {
			cvss, _ = ParseNVD(body)
			_ = body.Close()
		}
	}

	entries, m := Build(Sources{
		KEV: kev, KEVAsOf: kevAsOf, KEVVer: kevVer,
		EPSS: epss, EPSSAsOf: epssAsOf,
		Exploits: exploits, Weaponized: weaponized, WeaponRank: weaponRank,
		Templates: templates, CVSS: cvss, SSVC: ssvc,
	})
	dataPath, err := Write(opts.OutDir, entries, m)
	if err != nil {
		return Manifest{}, "", err
	}

	// Offensive-face exploit-intel sidecar (ADR 0019), OPT-IN + best-effort: only when a source URL is
	// configured, and a failure never touches the corpus already written above. The sidecar is a SEPARATE
	// file (exploit_intel.json), so it cannot perturb the byte-stable dashboard corpus block.
	if opts.ExploitIntelURL != "" {
		if records, stats := fetchExploitIntel(ctx, opts.HTTPClient, opts.ExploitIntelURL); len(records) > 0 {
			if _, werr := WriteExploitIntel(opts.OutDir, records); werr == nil {
				logExploitIntelCoverage(stats)
			}
		}
	}

	return m, dataPath, nil
}

// maxFeedBody bounds every corpus-feed RESPONSE so a hostile/runaway/MITM'd feed host can't OOM the
// in-process refresher. The largest real feed (the EPSS .csv.gz) is a few MiB compressed; 64 MiB is
// ample. (The gunzipped EPSS stream is bounded separately in ParseEPSSGzip — that's the bomb guard.)
const maxFeedBody = 64 << 20

// limitedReadCloser caps reads at a ceiling while preserving the underlying Close.
type limitedReadCloser struct {
	r io.Reader
	c io.Closer
}

func (l limitedReadCloser) Read(p []byte) (int, error) { return l.r.Read(p) }
func (l limitedReadCloser) Close() error               { return l.c.Close() }

func httpGet(ctx context.Context, c *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tsengine-corpus-refresh")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	// Bound the (compressed) body for every feed — defense-in-depth against an oversized/runaway response.
	return limitedReadCloser{r: io.LimitReader(resp.Body, maxFeedBody), c: resp.Body}, nil
}

// logExploitIntelCoverage surfaces the offensive-corpus coverage gap so a raw:-only CVE that yields no
// skeleton is VISIBLE, not silently absent (§5.2). Best-effort logging only — never affects the corpus.
func logExploitIntelCoverage(stats ExploitIntelStats) {
	if stats.SkippedNoSkeletonCount == 0 {
		log.Printf("[corpus] exploit-intel: %d offensive skeletons built from %d CVE templates", stats.Built, stats.CVETemplates)
		return
	}
	sample := stats.SkippedNoSkeleton
	suffix := ""
	if stats.SkippedNoSkeletonCount > len(sample) {
		suffix = ", …"
	}
	log.Printf("[corpus] exploit-intel: %d offensive skeletons built from %d CVE templates; %d skipped (no HTTP skeleton — raw:-only/matcher-less, defender-face only) e.g. %v%s",
		stats.Built, stats.CVETemplates, stats.SkippedNoSkeletonCount, sample, suffix)
}

package threatintel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RefreshOptions configures an out-of-band corpus refresh.
type RefreshOptions struct {
	OutDir       string       // output dir (default "./corpus")
	HTTPClient   *http.Client // default: 120s timeout
	KEVURL       string       // override for tests
	EPSSURL      string       // override for tests
	ExploitDBURL string       // override for tests; best-effort (a fetch failure doesn't fail the refresh)
	NVDURL       string       // OPT-IN CVSS-vector source: only fetched when set. NVD is large + paginated, so
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

	// NVD CVSS vectors are OPT-IN + best-effort: only fetched when a URL is configured (a bulk mirror / pager),
	// and a failure never blocks the KEV+EPSS refresh.
	var cvss map[string]NVDEntry
	if opts.NVDURL != "" {
		if body, ferr := httpGet(ctx, opts.HTTPClient, opts.NVDURL); ferr == nil {
			cvss, _ = ParseNVD(body)
			_ = body.Close()
		}
	}

	entries, m := Build(kev, kevAsOf, kevVer, epss, epssAsOf, exploits, cvss)
	dataPath, err := Write(opts.OutDir, entries, m)
	if err != nil {
		return Manifest{}, "", err
	}
	return m, dataPath, nil
}

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
	return resp.Body, nil
}

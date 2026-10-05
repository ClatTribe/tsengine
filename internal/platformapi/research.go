package platformapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/research"
	"github.com/ClatTribe/tsengine/internal/store"
)

// research.go: the bounded, cited research fetch (internal/research) exposed to the tenant.
//
// It defaults to a finding's OWN cited advisory URLs — the links the KEV ingest already pinned on the
// finding — so the common case ("tell me more about this fresh CVE") needs no allowlist configuration
// and can never reach anything the finding did not already name. An operator may widen the allowlist
// with TSENGINE_RESEARCH_HOSTS for a target's own docs/changelogs; nothing else is fetchable.

// researchHostAllowlist is the operator-configured set of host suffixes the research tool may fetch,
// on TOP of a finding's own advisory hosts. Comma/space separated. Empty → only a finding's own
// advisory hosts are reachable (the safe default: the tool can widen understanding of a finding
// without becoming an open fetch surface).
func researchHostAllowlist() []string {
	raw := strings.FieldsFunc(os.Getenv("TSENGINE_RESEARCH_HOSTS"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// safeResearchFetcher does one SSRF-screened, byte-capped GET, reusing the public-only client the
// assess prober uses. It is the research.Fetcher: the allowlist/caps/pinning policy lives in the
// research package; this only reaches the network safely.
func safeResearchFetcher(ctx context.Context, rawURL string, maxBytes int) (research.Raw, error) {
	client := safeHTTPClient(8 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return research.Raw{}, err
	}
	req.Header.Set("User-Agent", assessUA)
	resp, err := client.Do(req)
	if err != nil {
		return research.Raw{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return research.Raw{}, fmt.Errorf("source returned HTTP %d", resp.StatusCode)
	}
	// +1 so research can tell a document that exactly hit the cap from one that was truncated.
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	if err != nil {
		return research.Raw{}, err
	}
	return research.Raw{Body: body, ContentType: resp.Header.Get("Content-Type")}, nil
}

// handleResearchFinding fetches the cited advisory material for one finding. The allowlist is the
// finding's OWN advisory hosts plus the operator's configured set, so a tenant cannot aim the fetcher
// at a host the finding never referenced unless the operator allowed it.
func (d Deps) handleResearchFinding(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	var advisories []string
	found := false
	for _, f := range findings {
		if f.ID == id {
			found = true
			if f.ThreatIntel != nil {
				advisories = f.ThreatIntel.Advisories
			}
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errBody("no such finding in this workspace"))
		return
	}
	urls := research.AdvisoryURLs(advisories)
	if len(urls) == 0 {
		// Honest: this finding cites no researchable advisory. Not an error, and not an empty fetch
		// result that reads as "we looked and found nothing" — the finding named nothing to look at.
		writeJSON(w, http.StatusOK, map[string]any{
			"finding_id": id, "result": research.Result{},
			"note": "This finding cites no vendor-advisory URL to research. Advisory links come from the KEV feed and ride CVE-bearing findings.",
		})
		return
	}
	allow := researchHostAllowlist()
	for _, u := range urls {
		allow = append(allow, hostOf(u))
	}
	fetch := d.ResearchFetch
	if fetch == nil {
		fetch = safeResearchFetcher
	}
	res := research.Gather(r.Context(), fetch, urls, research.Options{AllowedHostSuffixes: allow})
	writeJSON(w, http.StatusOK, map[string]any{"finding_id": id, "result": res})
}

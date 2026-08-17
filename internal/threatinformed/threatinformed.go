// Package threatinformed turns the pinned threat-intel corpus into DISCOVERY
// targeting — the "threat-informed defense" loop the engine was missing.
//
// # THE GAP THIS CLOSES
//
// The engine already ships a KEV/EPSS/ExploitDB/CVSS corpus, but it was used
// only in the L1.5 hook chain — i.e. AFTER a finding exists, as annotation
// (CLAUDE.md §7). Nothing in the discovery path consulted it: which templates
// a scan runs was a static, hardcoded list ("api,graphql,jwt,oauth", a
// port→tags map). So the engine could hold the fact that CVE-X is being
// actively exploited in the wild against Apache httpd, detect Apache httpd on
// the target, and still never probe for CVE-X — because probe selection and
// threat intel never met.
//
// That is a DISCOVERY weakness, and discovery is the measured weak spot of
// autonomous security agents (frontier agents patch ~90% of localized bugs but
// only ~13-34% end-to-end, where the missing piece is finding the bug). The fix
// here is deliberately NOT "make the LLM search harder": it is to spend the
// scan's probe budget where world-state intel says the real risk is. That is
// how a human security engineer works — they read the KEV catalog and ask "do
// we run any of this?" — and it needs no LLM, so it is deterministic,
// reproducible, and free.
//
// GROUNDING (§10)
//
// A probe is emitted ONLY for a CVE that really appears in the pinned corpus
// with a real exploitation signal (KEV listing / EPSS score / public exploit).
// Nothing is inferred about a CVE that isn't there, no CVE id is ever
// synthesized, and a product match must come from the corpus's own KEV
// vendor/product strings — never from a guess about what a CVE "probably"
// affects. An empty corpus, or a target with no detected technology, yields
// targeted probes only where the evidence supports them (see Plan).
//
// # BOUNDING
//
// The plan is capped (MaxProbes, default 50 — the cost twin of
// TSENGINE_FANOUT_MAX_URLS / TSENGINE_ESCALATION_MAX) and ranked, so a
// 1,400-entry KEV catalog can never turn "targeted depth" into an unbounded
// scan. Ranking is by real exploitation likelihood, so the cap keeps the
// probes that matter.
package threatinformed

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Observation is a piece of technology the scan actually OBSERVED on the
// target — an nmap/httpx product+version, a syft package. It is the grounded
// input for targeting: the same signal the service_eol hook consumes
// (finding.ToolArgs["product"]/["version"]).
type Observation struct {
	Product string // e.g. "Apache httpd", "OpenSSH", "nginx"
	Version string // e.g. "2.4.7" (optional; targeting works without it)
	Port    int    // optional — where it was seen
	URL     string // optional — the endpoint to probe
}

// Probe is one targeted check the discovery stage should run: a specific CVE
// template, with the evidence that justified selecting it.
type Probe struct {
	CVE        string  // the CVE to probe (a real corpus key)
	TemplateID string  // nuclei template id (nuclei names CVE templates by id)
	Reason     Reason  // WHY this was selected — the audit trail
	Priority   float64 // higher runs first; derived from the intel, not invented
	Product    string  // the observed product this targets ("" = intel-only)
	URL        string  // the endpoint to probe, when known
}

// Reason is the grounded justification for a probe. Every field is a fact read
// from the pinned corpus, so an operator can audit why a probe ran.
type Reason struct {
	KEV           bool    // CISA KEV: exploited in the wild (BOD 22-01)
	EPSS          float64 // FIRST.org exploitation probability [0,1]
	PublicExploit bool    // an Exploit-DB / PoC reference exists
	ProductMatch  bool    // the corpus's KEV product matched an observed product
	KEVProduct    string  // what the catalog says is affected
}

// Options tunes selection. Zero value uses the documented defaults.
type Options struct {
	MaxProbes    int     // cap (default 50)
	MinEPSS      float64 // EPSS floor for intel-only probes (default 0.10)
	IntelOnly    bool    // when true, also plan probes with no product match
	MaxIntelOnly int     // sub-cap for unmatched probes (default 10)
}

func (o Options) withDefaults() Options {
	if o.MaxProbes <= 0 {
		o.MaxProbes = 50
	}
	if o.MinEPSS <= 0 {
		o.MinEPSS = 0.10
	}
	if o.MaxIntelOnly <= 0 {
		o.MaxIntelOnly = 10
	}
	return o
}

// Corpus is the subset of the threat-intel corpus needed for targeting: a
// CVE → intel map. It mirrors internal/corpus/threatintel's on-disk shape
// (map[cve]Entry) without importing it, so this package stays dependency-light
// and testable with a literal.
type Corpus map[string]Entry

// Entry is one CVE's exploitation intel (the targeting-relevant subset).
type Entry struct {
	KEV      *types.KEVStatus
	EPSS     *types.EPSSScore
	Exploits []string
}

// Plan selects the CVE probes worth running against the observed technology,
// ranked by real-world exploitation likelihood and bounded by opts.MaxProbes.
//
// Selection is evidence-ordered:
//
//  1. PRODUCT-MATCHED + KEV — the corpus says this CVE is exploited in the
//     wild, and its catalogued product matches something we actually saw on
//     this target. The strongest possible reason to probe.
//  2. PRODUCT-MATCHED + high EPSS / public exploit — likely exploitable
//     against tech we're running.
//  3. INTEL-ONLY KEV (opts.IntelOnly) — exploited in the wild but we couldn't
//     confirm the product from recon. Sub-capped, because it's speculative
//     breadth rather than targeting; OFF by default so the default plan is
//     purely evidence-targeted.
//
// A CVE with no exploitation signal at all is never probed here: that's the
// job of the always-on anchor templates, not of targeted depth.
func Plan(c Corpus, observed []Observation, opts Options) []Probe {
	opts = opts.withDefaults()
	if len(c) == 0 {
		return nil
	}

	// Index observations by normalized product for matching.
	type obs struct {
		o    Observation
		norm string
	}
	var obsList []obs
	for _, o := range observed {
		if n := normalize(o.Product); n != "" {
			obsList = append(obsList, obs{o: o, norm: n})
		}
	}

	var matched, intelOnly []Probe
	for cve, e := range c {
		kev := e.KEV != nil && e.KEV.Listed
		epss := 0.0
		if e.EPSS != nil {
			epss = e.EPSS.Score
		}
		pub := len(e.Exploits) > 0

		// No exploitation signal → not a targeted probe candidate (§10: we
		// don't probe on absence of evidence).
		if !kev && epss < opts.MinEPSS && !pub {
			continue
		}

		// Try to ground the CVE to an observed product via the corpus's own
		// KEV vendor/product strings. Never guess the affected product.
		kevProduct := ""
		if e.KEV != nil {
			kevProduct = strings.TrimSpace(e.KEV.Product)
		}
		kevVendor := ""
		if e.KEV != nil {
			kevVendor = strings.TrimSpace(e.KEV.Vendor)
		}

		hit := false
		var hitObs Observation
		if kevProduct != "" || kevVendor != "" {
			for _, ob := range obsList {
				if productMatches(ob.norm, kevProduct, kevVendor) {
					hit, hitObs = true, ob.o
					break
				}
			}
		}

		r := Reason{KEV: kev, EPSS: epss, PublicExploit: pub, ProductMatch: hit, KEVProduct: kevProduct}
		p := Probe{
			CVE:        cve,
			TemplateID: cve, // nuclei names its CVE templates by the CVE id
			Reason:     r,
			Priority:   priority(r),
		}
		if hit {
			p.Product, p.URL = hitObs.Product, hitObs.URL
			matched = append(matched, p)
		} else if opts.IntelOnly {
			intelOnly = append(intelOnly, p)
		}
	}

	sortProbes(matched)
	sortProbes(intelOnly)

	// Product-matched probes are the plan; intel-only breadth fills the
	// remaining budget up to its own sub-cap.
	out := matched
	if len(intelOnly) > 0 {
		room := opts.MaxProbes - len(out)
		if room > opts.MaxIntelOnly {
			room = opts.MaxIntelOnly
		}
		if room > 0 {
			if room > len(intelOnly) {
				room = len(intelOnly)
			}
			out = append(out, intelOnly[:room]...)
		}
	}
	if len(out) > opts.MaxProbes {
		out = out[:opts.MaxProbes]
	}
	return out
}

// priority scores a probe by real exploitation evidence. KEV dominates (it is
// observed in-the-wild exploitation, not a prediction), then EPSS probability,
// then the existence of a public exploit, and a product match outranks the
// same evidence without one.
func priority(r Reason) float64 {
	p := 0.0
	if r.KEV {
		p += 100
	}
	p += r.EPSS * 50 // EPSS is [0,1]; a 1.0 is worth half a KEV listing
	if r.PublicExploit {
		p += 10
	}
	if r.ProductMatch {
		p += 25
	}
	return p
}

func sortProbes(ps []Probe) {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Priority != ps[j].Priority {
			return ps[i].Priority > ps[j].Priority
		}
		return ps[i].CVE < ps[j].CVE // deterministic tie-break
	})
}

// normalize lowercases and strips the noise words nmap/httpx add to product
// banners so "Apache httpd" and CISA's "HTTP Server" can meet.
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, drop := range []string{" httpd", " server", " http server", " web server"} {
		s = strings.TrimSuffix(s, drop)
	}
	return strings.TrimSpace(s)
}

// productMatches decides whether an observed product corresponds to a KEV
// catalog entry. CISA splits the technology across vendorProject ("Apache")
// and product ("HTTP Server"), while scanners report a single banner ("Apache
// httpd"), so a match on EITHER side counts — but only via real substring
// containment between real strings, never a fuzzy guess.
func productMatches(observedNorm, kevProduct, kevVendor string) bool {
	if observedNorm == "" {
		return false
	}
	for _, cand := range []string{kevProduct, kevVendor} {
		c := normalize(cand)
		if c == "" {
			continue
		}
		if strings.Contains(observedNorm, c) || strings.Contains(c, observedNorm) {
			return true
		}
	}
	return false
}

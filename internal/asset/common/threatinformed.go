package common

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/threatinformed"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ThreatInformedEscalation is the glue that lets THREAT INTEL DRIVE DISCOVERY:
// it reads the technology a scan actually observed (nmap/httpx product+version
// on its findings), asks internal/threatinformed which CVEs are worth probing
// against that technology per the pinned corpus (KEV / EPSS / public exploit),
// and returns ONE bounded nuclei dispatch running exactly those templates.
//
// This is the deterministic escalation shape of CLAUDE.md §5.3 — a real signal
// (we are running a product the KEV catalog says is being exploited) gates a
// depth probe. It is not a blanket template sweep, and it needs no LLM.
//
// Returns nil (a graceful no-op) when: no corpus is configured, no product was
// observed, nothing in the corpus matches, or nuclei isn't registered. Callers
// append the result to their own trigger-derived dispatches.
//
// Grounding (§10): every probed CVE is a real corpus entry with a real
// exploitation signal, matched to a product the scan really saw. Nothing is
// probed on absence of evidence.
func ThreatInformedEscalation(findings []types.Finding) []asset.Dispatch {
	corpus, ok := threatinformed.CorpusFromEnv()
	if !ok {
		return nil
	}
	observed := ObservationsFromFindings(findings)
	if len(observed) == 0 {
		return nil
	}
	probes, untestable := threatinformed.PlanWithGaps(corpus, observed, threatinformed.Options{
		MaxProbes: threatInformedMax(),
	})
	// The untestable set is reported by ThreatInformedGaps through the CoverageReporter
	// seam, not here: this function returns dispatches and has no finding to carry it on,
	// and reporting the same gap from two places lets them disagree.
	_ = untestable
	if len(probes) == 0 {
		return nil
	}
	nuc, ok := tool.Get("nuclei")
	if !ok {
		return nil
	}

	// Batch the selected templates into ONE nuclei run (-id takes a
	// comma-separated list), so targeted depth costs a single dispatch rather
	// than N. Target the host/endpoint the matching product was seen on.
	ids := make([]string, 0, len(probes))
	target := ""
	for _, p := range probes {
		ids = append(ids, p.TemplateID)
		if target == "" && p.URL != "" {
			target = p.URL
		}
	}
	args := tool.Args{"id": strings.Join(ids, ",")}
	if target != "" {
		args["target"] = target
	}
	return []asset.Dispatch{{
		Tool:          nuc,
		Args:          args,
		EscalatedFrom: fmt.Sprintf("threat-intel→nuclei(%d KEV/EPSS-targeted templates)", len(ids)),
	}}
}

// ObservationsFromFindings extracts the observed technology from findings.
// Every value read is a fact a real tool reported — never an inference about
// what the target "probably" runs (§10). The per-tool arg shapes differ, so all
// the real ones are honoured:
//
//   - nmap (ip): ToolArgs["product"] + ["version"] — the same signal the
//     service_eol L1.5 hook consumes.
//   - httpx (web): ToolArgs["webserver"] (e.g. "Apache/2.4.49") and ["tech"]
//     (comma-separated -tech-detect output, e.g. "PHP,WordPress").
//   - grype/syft (container, repository): ToolArgs["pkg"] +
//     ["installed_version"].
//
// A "product/version" embedded in one banner string ("Apache/2.4.49") is split
// on the slash, since KEV catalogs the product name alone.
func ObservationsFromFindings(findings []types.Finding) []threatinformed.Observation {
	seen := map[string]bool{}
	var out []threatinformed.Observation

	add := func(product, version, endpoint, port string) {
		product = strings.TrimSpace(product)
		if product == "" {
			return
		}
		// httpx reports "Apache/2.4.49" in one field; KEV names the product.
		if version == "" {
			if name, ver, found := strings.Cut(product, "/"); found {
				product, version = strings.TrimSpace(name), strings.TrimSpace(ver)
			}
		}
		key := strings.ToLower(product) + "@" + version
		if seen[key] {
			return
		}
		seen[key] = true
		o := threatinformed.Observation{Product: product, Version: version, URL: endpoint}
		if p, err := strconv.Atoi(strings.TrimSpace(port)); err == nil {
			o.Port = p
		}
		out = append(out, o)
	}

	for _, f := range findings {
		a := f.ToolArgs
		add(a["product"], a["version"], f.Endpoint, a["port"])       // nmap
		add(a["webserver"], "", f.Endpoint, a["port"])               // httpx
		add(a["pkg"], a["installed_version"], f.Endpoint, a["port"]) // grype/syft
		for _, t := range strings.Split(a["tech"], ",") {            // httpx -tech-detect
			add(t, "", f.Endpoint, a["port"])
		}
	}
	return out
}

// threatInformedMax bounds the targeted probe set. Mirrors the other cost
// guards (TSENGINE_FANOUT_MAX_URLS / TSENGINE_ESCALATION_MAX).
func threatInformedMax() int {
	if v := os.Getenv("TSENGINE_THREAT_PROBE_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 25
}

// ThreatInformedGaps declares the exploited CVEs that match software this scan actually
// observed and that we have NO WAY TO TEST — nuclei ships no template for them.
//
// This is the honest half of threat-informed discovery. The probe plan is capped, and a
// CVE with no template was previously dropped from it silently, so a clean probe report
// read as "we checked everything that matters" when it meant "we checked what we could".
// A KEV CVE against software we can see, which we cannot check, is precisely the thing an
// operator must not have to infer from an absence.
//
// TWO CLAIMS THIS DELIBERATELY DOES NOT MAKE:
//
//   - It does not say the target is vulnerable. Matching is on PRODUCT, not version —
//     threatinformed matches "Apache HTTP Server" against observed "Apache httpd", and
//     says nothing about whether 2.4.62 is affected by a 2.4.49 bug. Wording it as a
//     vulnerability would manufacture a finding out of a coverage gap.
//   - It does not assign a severity above informational. A check that did not run has no
//     evidence for one, and a high on an untested CVE is the same overclaim as a green
//     tick on an unscanned scope, pointed the other way.
//
// Returns nil when no corpus is configured, nothing was observed, or everything that
// matched was testable — the common case, and the one worth reaching.
func ThreatInformedGaps(findings []types.Finding) []types.Finding {
	corpus, ok := threatinformed.CorpusFromEnv()
	if !ok {
		return nil
	}
	observed := ObservationsFromFindings(findings)
	if len(observed) == 0 {
		return nil
	}
	_, untestable := threatinformed.PlanWithGaps(corpus, observed, threatinformed.Options{
		MaxProbes: threatInformedMax(),
	})
	if len(untestable) == 0 {
		return nil
	}
	// Group by the endpoint the product was seen on, so the gap sits where the software is
	// rather than as one lump against the target.
	byURL := map[string][]threatinformed.Probe{}
	for _, p := range untestable {
		byURL[p.URL] = append(byURL[p.URL], p)
	}
	urls := make([]string, 0, len(byURL))
	for u := range byURL {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	out := make([]types.Finding, 0, len(urls))
	for i, u := range urls {
		ps := byURL[u]
		ids := make([]string, 0, len(ps))
		kev := 0
		for _, p := range ps {
			ids = append(ids, p.CVE)
			if p.Reason.KEV {
				kev++
			}
		}
		sort.Strings(ids)
		product := ps[0].Product
		desc := fmt.Sprintf(
			"%d exploited CVE(s) are catalogued against %q, which this scan observed here, and nuclei "+
				"ships no template for any of them — so they were RANKED but NOT TESTED: %s.\n\n"+
				"This is a coverage gap, not a vulnerability. The match is on PRODUCT, not version, so "+
				"this does not say the target is affected; it says we could not check. Verify these by "+
				"another route (vendor advisory against the running version, an authenticated check, or "+
				"a purpose-built exploit test) rather than reading their absence from the probe results "+
				"as a clean bill of health.",
			len(ids), product, strings.Join(ids, ", "))
		if kev > 0 {
			desc += fmt.Sprintf("\n\n%d of them are on the CISA KEV catalogue (exploited in the wild).", kev)
		}
		f := types.Finding{
			ID:     fmt.Sprintf("ti-gap-%03d", i+1),
			RuleID: asset.CoverageRulePrefix + "threat-informed-untested-cve",
			Tool:   "coverage",
			// Informational: a check that did not run has no evidence for a severity.
			Severity:     types.SeverityInfo,
			Endpoint:     u,
			Title:        fmt.Sprintf("%d exploited CVE(s) against observed %s could not be tested", len(ids), product),
			Description:  desc,
			ToolArgs:     map[string]string{"product": product, "cves": strings.Join(ids, ","), "kev": strconv.Itoa(kev)},
			DiscoveredAt: time.Now().UTC(),
		}
		out = append(out, f)
	}
	return out
}

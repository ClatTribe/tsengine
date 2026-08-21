package common

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

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
	// The untestable set is CVEs that matched a product this scan really observed and that
	// nuclei has no template for. They are logged rather than silently dropped: a KEV CVE
	// against software we can see, which we cannot check, is exactly the thing an operator
	// must not learn about by inferring it from a probe report that looks clean. Logging is
	// the honest minimum here — this function returns dispatches, so it has no finding to
	// carry the gap on; surfacing it as a coverage gap on the scan is the follow-on.
	if len(untestable) > 0 {
		ids := make([]string, 0, len(untestable))
		for _, p := range untestable {
			ids = append(ids, p.CVE)
		}
		log.Printf("[threat-informed] %d exploited CVE(s) match observed software but have no nuclei template — NOT tested: %s",
			len(untestable), strings.Join(ids, ","))
	}
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

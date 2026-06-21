package cloudengine

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Agentless workload coverage (CWPP) — Phase 2 of the cloud-parity plan (ADR 0009). Wiz's
// flagship is scanning the disks/images of running workloads for vulnerabilities WITHOUT an
// in-VM agent. Our analog, true to §13 (wrap OSS, add no scanner): read the cloud inventory
// snapshot, extract the container images the running workloads reference, and route those
// images through our EXISTING container-image scanner (trivy image mode). "Agentless" because
// it reads the account inventory, not an agent inside the workload.
//
// Two deterministic, offline-testable halves live here:
//   1. WorkloadScanPlan — inventory → the deduped, capped list of images to scan (the plan the
//      orchestrator routes through trivy in the sandbox; the live run is sandbox-gated).
//   2. WorkloadExposures — given the scan results keyed back to nodes, emit the Wiz "toxic
//      combination": an internet-reachable workload running a critically-vulnerable image is a
//      remotely-exploitable entry point. Modeled as a one-hop internet→workload attack path so
//      it reuses every downstream renderer (severity, narrative, compliance).

const workloadScanMaxDefault = 100

// imageAttrKey is where a compute node carries the container image it runs (populated by the
// inventory ingest; see ADR 0009 — EC2 AMI disk scanning is a deeper, future step).
const imageAttrKey = "image"

// WorkloadImage is one container image referenced by running workloads — the unit the
// agentless scan routes through trivy. Deduped by image ref (scan each unique image once);
// Nodes lists every compute node that runs it so results fan back to all of them.
type WorkloadImage struct {
	Image       string   `json:"image"`
	Nodes       []string `json:"nodes"`
	Region      string   `json:"region,omitempty"`
	ComputeType string   `json:"compute_type,omitempty"` // ECS | EKS | Lambda | ...
}

// WorkloadVuln is the result of scanning one image, keyed back to its image ref. Produced by
// the orchestrator from the trivy run over WorkloadScanPlan (sandbox-gated); consumed by
// WorkloadExposures + Assess to emit toxic-combo findings.
type WorkloadVuln struct {
	Image    string `json:"image"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	TopCVE   string `json:"top_cve,omitempty"`
}

// WorkloadScanPlan extracts the deduped, capped list of container images the inventory's
// running workloads reference. Deterministic + sorted. The cap (TSENGINE_CLOUD_WORKLOAD_MAX,
// default 100) is the cost twin of the fan-out cap — a huge account can't turn an agentless
// pass into an unbounded image-scan storm.
func WorkloadScanPlan(snap *cloudgraph.Snapshot) []WorkloadImage {
	if snap == nil {
		return nil
	}
	byImage := map[string]*WorkloadImage{}
	for id, n := range snap.Nodes {
		img := imageRef(n)
		if img == "" {
			continue
		}
		w := byImage[img]
		if w == nil {
			w = &WorkloadImage{Image: img, Region: n.Region, ComputeType: computeType(n.Type)}
			byImage[img] = w
		}
		w.Nodes = append(w.Nodes, id)
	}
	out := make([]WorkloadImage, 0, len(byImage))
	for _, w := range byImage {
		sort.Strings(w.Nodes)
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Image < out[j].Image })
	if max := workloadScanMax(); len(out) > max {
		out = out[:max]
	}
	return out
}

// WorkloadExposures emits a toxic-combo attack path for every internet-reachable workload that
// runs a vulnerable image (critical or high CVE). This is the Wiz headline — a remotely
// reachable, vulnerable workload is an exploitable entry point, not just a config nit.
// Internal-only vulnerable workloads are NOT emitted here (their raw CVEs already ship from the
// trivy run); WorkloadExposures is specifically the internet-exposed toxic combination.
// Grounded (§10): fires only when the node is internet-reachable per config AND its image
// genuinely scanned vulnerable. Deduped against nodes already on a discovered path.
func WorkloadExposures(snap *cloudgraph.Snapshot, vulns []WorkloadVuln, covered map[string]bool) []types.AttackPath {
	if snap == nil || len(vulns) == 0 {
		return nil
	}
	byImage := map[string]WorkloadVuln{}
	for _, v := range vulns {
		if v.Critical > 0 || v.High > 0 {
			byImage[v.Image] = v
		}
	}
	type hit struct {
		node string
		v    WorkloadVuln
	}
	var hits []hit
	for id, n := range snap.Nodes {
		if covered[id] || !n.Public { // internet-reachable per config = the toxic-combo gate
			continue
		}
		if v, ok := byImage[imageRef(n)]; ok {
			hits = append(hits, hit{id, v})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].node < hits[j].node })

	out := make([]types.AttackPath, 0, len(hits))
	for i, h := range hits {
		n := snap.Node(h.node)
		p := cloudgraph.Path{
			Nodes: []string{cloudgraph.InternetID, h.node},
			Edges: []cloudgraph.Edge{{From: cloudgraph.InternetID, To: h.node, Kind: cloudgraph.EdgeNetworkReach}},
		}
		ap := buildFinding(snap, fmt.Sprintf("cwpp-%03d", i+1), p, 1, []types.EvidenceItem{workloadEvidence(n, h.v)})
		sev := "high-severity"
		if h.v.Critical > 0 {
			sev = "critical-severity"
		}
		ap.Narrative = fmt.Sprintf("%s (%s) is internet-reachable and runs an image with %s vulnerabilities (%s): a remotely-reachable, exploitable workload — the classic toxic combination of public exposure + a known-vulnerable workload.",
			dspmName(n), n.Type, sev, vulnSummary(h.v))
		ap.Remediation = fmt.Sprintf("Patch/rebuild the workload image (%s) to clear the vulnerabilities, and/or remove public network exposure so it is not internet-reachable.", imageRef(n))
		out = append(out, ap)
	}
	return out
}

func imageRef(n *cloudgraph.Node) string {
	if n == nil || n.Attrs == nil {
		return ""
	}
	return strings.TrimSpace(n.Attrs[imageAttrKey])
}

// computeType pulls a short workload kind from an "AWS::ECS::TaskDefinition"-style type.
func computeType(t string) string {
	parts := strings.Split(t, "::")
	if len(parts) >= 2 {
		return parts[1] // AWS::ECS::… → ECS
	}
	return t
}

func vulnSummary(v WorkloadVuln) string {
	var b strings.Builder
	if v.Critical > 0 {
		fmt.Fprintf(&b, "%d critical", v.Critical)
	}
	if v.High > 0 {
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d high", v.High)
	}
	if v.TopCVE != "" {
		fmt.Fprintf(&b, "; e.g. %s", v.TopCVE)
	}
	return b.String()
}

func workloadEvidence(n *cloudgraph.Node, v WorkloadVuln) types.EvidenceItem {
	return types.EvidenceItem{
		Query:       fmt.Sprintf("trivy image %s", v.Image),
		Observation: fmt.Sprintf("workload %s is public=true and its image scanned %d critical / %d high (top: %s)", n.ID, v.Critical, v.High, v.TopCVE),
		AtRung:      2, // a real image scan (live tool result), not just config reasoning
	}
}

func workloadScanMax() int {
	if s := os.Getenv("TSENGINE_CLOUD_WORKLOAD_MAX"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return workloadScanMaxDefault
}

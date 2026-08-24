// Package cloudagent is the AI Cloud Security Engineer as an LLM AGENT (the
// VulnAgent shape, CLAUDE.md §10): the model is the brain, and the deterministic
// components (cloudgraph reachability, cloudiam effective-perms, the attack-path
// enumerator, the remediation generator) are TOOLS it calls to access and assess
// resources and determine issues. There is NO fixed deterministic spine driving
// the show — the LLM reasons; the tools answer precise questions and refuse to
// let it record a finding the graph doesn't support (evidence grounding, the
// anti-hallucination guard that replaces the old process-reproducibility mandate).
package cloudagent

import (
	"fmt"
	"github.com/ClatTribe/tsengine/internal/estategraph"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/estatedetect"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// toolDef is one hand: the name + one-line help the brain sees, and the handler.
type toolDef struct {
	name    string
	help    string
	handler func(cc *Context, args map[string]any) string
}

// tools is the cloud tool catalog (the ≤12 "hands").
func tools() []toolDef {
	return []toolDef{
		{"list_resources", "list_resources(kind?, only_sensitive?) — inventory: ids/names/kind/flags. kind ∈ resource|principal|data|network", tList},
		{"get_resource", "get_resource(id, live?) — one resource's metadata + its outgoing edges (moves an attacker could make from it). Pass live:true to ALSO re-read it from the account right now: everything else you see was captured before this investigation began, so a flag a path turns on (public, privileged) may already have changed. Do that before recording an issue whose severity depends on such a flag. Read-only; it answers AGREES / DIFFERS / COULD NOT CHECK and never reads an unread surface as an absent resource.", tGet},
		{"resolve_access", "resolve_access(principal, resource, action?) — does the principal have an effective path of access to the resource? (graph reachability over resolved IAM). Pass action (a provider action e.g. iam:PassRole, s3:GetObject) to ALSO run a PROVIDER dry-run: ask AWS/GCP/Azure's own policy simulator whether the move would be ALLOWED right now, WITHOUT performing it — upgrading the answer from config-possible (our graph) to provider-confirmed (the authority that enforces the policy). Read-only; ALLOW=provider-confirmed AUTHORIZATION for that ONE action (NOT proof of exploitability \u2014 network reachability, credential acquisition and the rest of the workflow stay unproven), DENY=authoritative refusal for that tuple (do not record a path that depends on it), UNKNOWN=unproven (never \"safe\").", tResolve},
		{"find_paths", "find_paths(target) — concrete attack paths from the internet/public surface to the target node, if any", tFindPaths},
		{"blast_radius", "blast_radius(principal) — every crown jewel (sensitive data / privileged identity) reachable if this principal is compromised", tBlast},
		{"enumerate_attack_paths", "enumerate_attack_paths() — the deterministic engine's candidate attack paths (a fast prepass to seed your investigation; verify/extend them)", tEnumerate},
		{"detect_privesc", "detect_privesc(principal) — known IAM privilege-escalation moves available to the principal", tPrivesc},
		{"estate_context", "estate_context(id | chokepoints:true) — what the WHOLE estate knows about this node: which surfaces asserted it (code/cloud/saas/identity/warehouse), and every neighbour in or out with the evidence for that hop. Use it to PIVOT off a cross-surface foothold — e.g. a leaked key's origin in code, or what else can reach a principal. Pass chokepoints:true (no id) for the estate-wide 'what to fix first' view: the single nodes the most internet→crown routes cross. Cloud-only questions stay with get_resource/find_paths. Context only: record_issue grounds against the CLOUD graph, so do not build a path out of estate ids — cross-surface paths are reported by the estate detector.", tEstate},
		{"get_findings", "get_findings(resource?) — prowler config-bad findings (the 'tools say' lens; most are NOT exploitable — your job is to tell which are)", tFindings},
		{"record_issue", "record_issue(target, path[], severity, rationale, evidence[]) — commit a REAL attack path you've determined. REJECTED unless the path actually exists in the graph and ends at a crown jewel.", tRecord},
		{"propose_fix", "propose_fix(issue_id) — generate an applyable, cloudiam-verified remediation that cuts the recorded issue's cheapest edge", tFix},
		{"finish", "finish(summary) — end the investigation and emit the executive summary", tFinish},
	}
}

// --- handlers ---

func tList(cc *Context, args map[string]any) string {
	kind := argStr(args, "kind")
	onlySens := argBool(args, "only_sensitive")
	var rows []string
	ids := sortedNodeIDs(cc.Snap)
	for _, id := range ids {
		n := cc.Snap.Nodes[id]
		if kind != "" && string(n.Kind) != kind {
			continue
		}
		if onlySens && !(cloudgraph.SensitiveData(n) || cloudgraph.PrivilegedIdentity(n)) {
			continue
		}
		flags := flagsOf(n)
		rows = append(rows, fmt.Sprintf("- %s [%s]%s", id, n.Kind, flags))
		if len(rows) >= 60 {
			rows = append(rows, fmt.Sprintf("... (%d more; narrow with kind/only_sensitive)", len(ids)-60))
			break
		}
	}
	if len(rows) == 0 {
		return "no resources match"
	}
	return strings.Join(rows, "\n")
}

func tGet(cc *Context, args map[string]any) string {
	id := argStr(args, "id")
	n := cc.Snap.Node(id)
	if n == nil {
		return "ERROR: no such resource " + id
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s]%s type=%s\n", id, n.Kind, flagsOf(n), n.Type)
	out := outEdges(cc.Snap, id)
	if len(out) == 0 {
		b.WriteString("no outgoing edges (an attacker here cannot move further)")
	} else {
		b.WriteString("moves from here:\n")
		for _, e := range out {
			cond := ""
			if e.Condition != "" {
				cond = " (gated by runtime condition: " + e.Condition + ")"
			}
			fmt.Fprintf(&b, "  -%s-> %s%s\n", e.Kind, e.To, cond)
		}
	}
	// Live re-read rides on get_resource rather than taking a catalog slot of its own — the same
	// reason estate_context is one tool and not three (§2.6: past ~12 hands, tool-use accuracy
	// degrades). Appending it also puts the graph view and the live view in ONE observation, so the
	// agent compares them directly instead of holding two answers in its head.
	if argBool(args, "live") {
		b.WriteString("\n" + tCheckLive(cc, args))
	}
	return b.String()
}

func tResolve(cc *Context, args map[string]any) string {
	p, r := argStr(args, "principal"), argStr(args, "resource")
	if cc.Snap.Node(p) == nil {
		return "ERROR: no such principal " + p
	}
	if cc.Snap.Node(r) == nil {
		return "ERROR: no such resource " + r
	}
	var b strings.Builder
	if reachableFrom(cc.Snap, p)[r] {
		fmt.Fprintf(&b, "YES — %s can reach %s over the resolved access/assume graph (effective IAM already applied at ingest).", p, r)
	} else {
		fmt.Fprintf(&b, "NO — %s has no effective path of access to %s. A prowler finding here is likely inert.", p, r)
	}
	// Provider dry-run rides on resolve_access (it does NOT take its own catalog slot — the ≤12 cap,
	// §2.6, is why check_live rides on get_resource too). When the model supplies an action, it wants
	// the authoritative answer, not just our graph's: run the provider simulator and append its
	// verdict in the SAME observation so the two views sit side by side.
	if action := strings.TrimSpace(argStr(args, "action")); action != "" {
		b.WriteString("\n" + tCheckReachable(cc, args))
	}
	return b.String()
}

func tFindPaths(cc *Context, args map[string]any) string {
	target := argStr(args, "target")
	if cc.Snap.Node(target) == nil {
		return "ERROR: no such target " + target
	}
	var found []string
	seen := map[string]bool{}
	for _, entry := range entryPoints(cc.Snap) {
		paths := cc.Snap.FindPaths(entry, func(n *cloudgraph.Node) bool { return n != nil && n.ID == target }, cloudgraph.AllAttackEdges, 8, 5)
		for _, p := range paths {
			key := strings.Join(p.Nodes, ">")
			if seen[key] {
				continue
			}
			seen[key] = true
			found = append(found, "  "+strings.Join(p.Nodes, " -> ")+condTag(p))
		}
	}
	if len(found) == 0 {
		return fmt.Sprintf("no attack path from the internet/public surface reaches %s (not externally exploitable as modelled)", target)
	}
	return fmt.Sprintf("%d path(s) to %s:\n%s", len(found), target, strings.Join(found, "\n"))
}

func tBlast(cc *Context, args map[string]any) string {
	p := argStr(args, "principal")
	if cc.Snap.Node(p) == nil {
		return "ERROR: no such principal " + p
	}
	reach := reachableFrom(cc.Snap, p)
	var jewels []string
	for id := range reach {
		if id == p {
			continue
		}
		if n := cc.Snap.Node(id); n != nil && (cloudgraph.SensitiveData(n) || cloudgraph.PrivilegedIdentity(n)) {
			jewels = append(jewels, "  "+id+flagsOf(n))
		}
	}
	sort.Strings(jewels)
	if len(jewels) == 0 {
		return fmt.Sprintf("blast radius of %s: %d resources reachable, but NO crown jewels — low impact.", p, len(reach)-1)
	}
	return fmt.Sprintf("blast radius of %s: %d resources reachable, %d crown jewel(s):\n%s", p, len(reach)-1, len(jewels), strings.Join(jewels, "\n"))
}

func tEnumerate(cc *Context, _ map[string]any) string {
	a := cloudengine.Assess(cc.Snap, cc.Prowler, cloudengine.SnapshotOracle{}, cloudengine.Options{MaxHypotheses: cc.MaxHyp})
	if len(a.Paths) == 0 {
		return "the deterministic prepass found no real-impact attack paths. The account may be clean, or the real risk is a shape the prepass doesn't model — investigate with the other tools."
	}
	var rows []string
	for _, p := range a.Paths {
		end := ""
		if n := len(p.Graph.Nodes); n > 0 {
			end = p.Graph.Nodes[n-1].ID
		}
		rows = append(rows, fmt.Sprintf("  target=%s  impact=%.2f  %s", end, p.RealImpact.Score, p.Narrative))
	}
	return fmt.Sprintf("deterministic prepass — %d candidate path(s):\n%s\n(verify/extend these, then record_issue the ones you confirm)", len(a.Paths), strings.Join(rows, "\n"))
}

func tPrivesc(cc *Context, args map[string]any) string {
	p := argStr(args, "principal")
	if cc.Snap.Node(p) == nil {
		return "ERROR: no such principal " + p
	}
	var moves []string
	for _, e := range outEdges(cc.Snap, p) {
		if e.Kind == cloudgraph.EdgePrivesc {
			moves = append(moves, fmt.Sprintf("  -> %s via %s", e.To, e.Detail))
		}
	}
	if len(moves) == 0 {
		return fmt.Sprintf("%s has no known privilege-escalation move.", p)
	}
	return fmt.Sprintf("%s can privilege-escalate:\n%s", p, strings.Join(moves, "\n"))
}

func tFindings(cc *Context, args map[string]any) string {
	res := argStr(args, "resource")
	var rows []string
	for _, f := range cc.Prowler {
		r := resourceOf(f)
		if res != "" && r != res {
			continue
		}
		rows = append(rows, fmt.Sprintf("  %s  [%s]  %s", f.ID, f.Severity, r))
		if len(rows) >= 50 {
			rows = append(rows, "... (more; filter by resource)")
			break
		}
	}
	if len(rows) == 0 {
		return "no prowler findings match"
	}
	return fmt.Sprintf("%d prowler finding(s) (config-bad; decide which are exploitable):\n%s", len(rows), strings.Join(rows, "\n"))
}

func tRecord(cc *Context, args map[string]any) string {
	target := argStr(args, "target")
	path := argStrList(args, "path")
	// GROUNDING: the claimed path must actually exist in the graph and end at a
	// crown jewel. This is what stops the LLM inventing an attack path.
	if err := validatePath(cc.Snap, path, target); err != nil {
		// A path built out of estate_context nodes fails this check for a reason the generic
		// message describes WRONGLY: it says "start at the internet or a public resource", which
		// invites the model to go hunting for a cloud entry point that does not exist — or to
		// invent one. Name the actual boundary instead. This is a scope limit, not a judgement
		// that the path is false: the cross-surface path is real and IS reported, by the
		// deterministic estate detector, which owns findings that span surfaces.
		if id := estateOnlyNode(cc, path); id != "" {
			return "REJECTED (out of scope for this tool): " + id + " is an estate node, not a resource in " +
				"this cloud account, so record_issue cannot ground a path through it. record_issue commits " +
				"CLOUD-grounded paths only. The cross-surface path is already reported separately by the " +
				"estate detector — use estate_context to UNDERSTAND and prioritise what you find in the " +
				"cloud (e.g. that this principal is reachable at all), and record the cloud-grounded issues."
		}
		return "REJECTED (not grounded): " + err.Error() + " — use find_paths / resolve_access to ground your claim before recording."
	}
	cc.issueN++
	is := Issue{
		ID: fmt.Sprintf("ai-%03d", cc.issueN), Target: target,
		TargetName: nameOf(cc.Snap, target), Path: path,
		Severity: argStr(args, "severity"), Rationale: argStr(args, "rationale"),
		Evidence: argStrList(args, "evidence"),
	}
	// Grounding upgrade (ADR 0024 P1): stamp provider-confirmed AUTHORIZATION only when EVERY
	// authorization-requiring hop on this path was confirmed ALLOW by the provider. One allowed hop
	// does not prove a multi-hop path (§10). Not required — a run with no Prober still records
	// config-possible paths exactly as before; this only adds the stronger, fully-backed claim.
	plan := cc.authorizationProofPlan(path)
	is.ProofPlan = &plan
	// ProviderConfirmed stays the strict every-hop claim from C2 — a DENIED or PARTIAL path is not
	// confirmed. Kept as a separate bool rather than derived at every read site, because a consumer
	// that forgets to check Status would otherwise treat any non-empty plan as a confirmation.
	is.ProviderConfirmed = plan.Status == PathConfirmed
	is.AuthorizationCoverage = plan.Coverage()
	cc.Issues = append(cc.Issues, is)
	return fmt.Sprintf("recorded %s: %s (grounded — the path exists and reaches a crown jewel). Consider propose_fix(%s).", is.ID, strings.Join(path, " -> "), is.ID)
}

func tFix(cc *Context, args map[string]any) string {
	id := argStr(args, "issue_id")
	idx := -1
	for i := range cc.Issues {
		if cc.Issues[i].ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return "ERROR: no recorded issue " + id
	}
	ap := pathToAttackPath(cc.Snap, cc.Issues[idx].ID, cc.Issues[idx].Path)
	arts := cloudengine.GenerateRemediations(&types.AIAssessment{Paths: []types.AttackPath{ap}})
	if len(arts) == 0 {
		return "no remediation could be generated for that path"
	}
	art := arts[0]
	cc.Issues[idx].Remediation = art.Title
	cc.Issues[idx].FixKind = art.Kind
	cc.Issues[idx].FixContent = art.Content
	cc.Issues[idx].FixVerified = art.Verified
	v := "not auto-verified (manual review)"
	if art.Verified {
		v = "VERIFIED — cloudiam confirms it cuts the path"
	}
	return fmt.Sprintf("fix for %s: %s [%s, %s]\n%s", id, art.Title, art.Kind, v, art.Content)
}

func tFinish(cc *Context, args map[string]any) string {
	cc.Summary = argStr(args, "summary")
	cc.Done = true
	return "investigation closed."
}

// --- graph helpers ---

func adjacency(snap *cloudgraph.Snapshot) map[string][]cloudgraph.Edge {
	m := map[string][]cloudgraph.Edge{}
	for _, e := range snap.Edges {
		m[e.From] = append(m[e.From], e)
	}
	return m
}

func outEdges(snap *cloudgraph.Snapshot, id string) []cloudgraph.Edge {
	var out []cloudgraph.Edge
	for _, e := range snap.Edges {
		if e.From == id {
			out = append(out, e)
		}
	}
	return out
}

func entryPoints(snap *cloudgraph.Snapshot) []string {
	out := []string{cloudgraph.InternetID}
	for id, n := range snap.Nodes {
		if n.Public && id != cloudgraph.InternetID {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func reachableFrom(snap *cloudgraph.Snapshot, start string) map[string]bool {
	adj := adjacency(snap)
	seen := map[string]bool{start: true}
	q := []string{start}
	for len(q) > 0 {
		n := q[0]
		q = q[1:]
		for _, e := range adj[n] {
			if cloudgraph.AllAttackEdges[e.Kind] && e.Condition == "" && !seen[e.To] {
				seen[e.To] = true
				q = append(q, e.To)
			}
		}
	}
	return seen
}

func edgeBetween(snap *cloudgraph.Snapshot, a, b string) (cloudgraph.Edge, bool) {
	for _, e := range snap.Edges {
		if e.From == a && e.To == b && cloudgraph.AllAttackEdges[e.Kind] {
			return e, true
		}
	}
	return cloudgraph.Edge{}, false
}

// estateOnlyNode returns the first path node that the cloud account does not contain but the
// estate graph does — i.e. the model pivoted through a cross-surface node. Empty when the path
// fails for an ordinary cloud reason, so the normal grounding message still does its job.
func estateOnlyNode(cc *Context, path []string) string {
	if cc.Estate == nil {
		return ""
	}
	for _, id := range path {
		if cc.Snap != nil && cc.Snap.Node(id) != nil {
			continue
		}
		if id == cloudgraph.InternetID {
			continue
		}
		if _, ok := cc.Estate.Nodes[id]; ok {
			return id
		}
	}
	return ""
}

// validatePath is the grounding check for record_issue.
func validatePath(snap *cloudgraph.Snapshot, nodes []string, target string) error {
	if len(nodes) < 2 {
		return fmt.Errorf("a path needs at least 2 nodes (entry -> ... -> target)")
	}
	if nodes[len(nodes)-1] != target {
		return fmt.Errorf("the path must end at the target %q", target)
	}
	if !isEntry(snap, nodes[0]) {
		return fmt.Errorf("the path must start at the internet or a public resource, not %q", nodes[0])
	}
	for i := 0; i < len(nodes)-1; i++ {
		if _, ok := edgeBetween(snap, nodes[i], nodes[i+1]); !ok {
			return fmt.Errorf("there is no attack edge %s -> %s in this account; that path does not exist", nodes[i], nodes[i+1])
		}
	}
	end := snap.Node(target)
	if end == nil {
		return fmt.Errorf("no such target %q", target)
	}
	if !(cloudgraph.SensitiveData(end) || cloudgraph.PrivilegedIdentity(end)) {
		return fmt.Errorf("%q is not a crown jewel (sensitive data or privileged identity) — no real impact", target)
	}
	return nil
}

// edgeNeedsAuthorization reports whether traversing this edge kind is an IAM authorization decision
// the provider simulator can answer. A network_reach edge is a NETWORK fact (the runtime-preconditions
// rung, not this one), so it is out of scope here rather than silently treated as authorized.
func edgeNeedsAuthorization(k cloudgraph.EdgeKind) bool {
	switch k {
	case cloudgraph.EdgeAssumeRole, cloudgraph.EdgePassRole, cloudgraph.EdgeHasAccess,
		cloudgraph.EdgePrivesc, cloudgraph.EdgeSecretAccess:
		return true
	default:
		return false
	}
}

func pathToAttackPath(snap *cloudgraph.Snapshot, id string, nodes []string) types.AttackPath {
	g := types.PathGraph{}
	for _, n := range nodes {
		g.Nodes = append(g.Nodes, types.PathNode{ID: n, Label: nameOf(snap, n)})
	}
	for i := 0; i < len(nodes)-1; i++ {
		if e, ok := edgeBetween(snap, nodes[i], nodes[i+1]); ok {
			g.Edges = append(g.Edges, types.PathEdge{From: e.From, To: e.To, Kind: string(e.Kind)})
		}
	}
	return types.AttackPath{ID: id, Graph: g}
}

func isEntry(snap *cloudgraph.Snapshot, id string) bool {
	if id == cloudgraph.InternetID {
		return true
	}
	n := snap.Node(id)
	return n != nil && n.Public
}

func flagsOf(n *cloudgraph.Node) string {
	var f []string
	if n.Public {
		f = append(f, "public")
	}
	if n.Sensitive != cloudgraph.SensNone {
		f = append(f, "sensitive="+string(n.Sensitive))
	}
	if n.Privileged {
		f = append(f, "privileged")
	}
	if n.Name != "" {
		f = append(f, "name="+n.Name)
	}
	if len(f) == 0 {
		return ""
	}
	return " (" + strings.Join(f, ", ") + ")"
}

func condTag(p cloudgraph.Path) string {
	if p.Conditional() {
		return "  [conditioned — needs live validation]"
	}
	return ""
}

func nameOf(snap *cloudgraph.Snapshot, id string) string {
	if n := snap.Node(id); n != nil && n.Name != "" {
		return n.Name
	}
	return id
}

func sortedNodeIDs(snap *cloudgraph.Snapshot) []string {
	out := make([]string, 0, len(snap.Nodes))
	for id := range snap.Nodes {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// resourceOf mirrors the prowler endpoint join ("<svc> <resource> @region").
func resourceOf(f types.Finding) string {
	parts := strings.Fields(f.Endpoint)
	if len(parts) >= 2 {
		return parts[1]
	}
	return strings.TrimSpace(f.Endpoint)
}

func argStr(args map[string]any, k string) string {
	if v, ok := args[k].(string); ok {
		return v
	}
	return ""
}

func argBool(args map[string]any, k string) bool {
	b, _ := args[k].(bool)
	return b
}

func argStrList(args map[string]any, k string) []string {
	switch t := args[k].(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	}
	return nil
}

// tEstate is the cross-surface PIVOT. get_resource answers "what can I do from here" inside the
// cloud account; this answers "what does the rest of the estate know about this thing" — which
// surfaces asserted it, and every hop in or out WITH the evidence that proves it.
//
// It exists because the agent previously received cross-surface knowledge as Bridges []string: a
// rendered hint it could read but not follow. A hint tells you where to look once; a graph lets you
// keep asking. Grounded (§10): every edge printed carries the evidence that proved it, and
// estategraph refuses to hold an edge with none — so the agent cannot walk a hop nobody proved.
func tEstate(cc *Context, args map[string]any) string {
	if cc.Estate == nil || len(cc.Estate.Nodes) == 0 {
		return "the cross-surface estate graph is not available for this run — only this cloud " +
			"account is in view. Use get_resource / find_paths for cloud-only questions."
	}
	// estate_context(chokepoints:true) — the estate-wide "what to fix first" view: the single nodes
	// the most cross-surface internet→crown routes run through. Computed by the SAME enumeration the
	// estate detector emits its choke-point finding from, so the agent's priority can't disagree
	// with the finding the customer sees.
	if argBool(args, "chokepoints") || strings.EqualFold(argStr(args, "id"), "chokepoints") {
		return renderEstateChokePoints(estatedetect.ChokePoints(cc.Estate, estatedetect.Options{}))
	}
	id := argStr(args, "id")
	n, ok := cc.Estate.Nodes[id]
	if !ok {
		// Do not guess at a near-match: a fabricated node id is a fabricated pivot.
		return "ERROR: " + id + " is not a node in the estate graph. Ids are surface-qualified " +
			"(e.g. cloud:role/deploy, secret:akia..., code:repo/app.py)."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s]", n.ID, n.Kind)
	if n.Name != "" {
		fmt.Fprintf(&b, " %q", n.Name)
	}
	if len(n.Surfaces) > 1 {
		// The headline fact: two surfaces asserting one node IS the cross-surface join.
		fmt.Fprintf(&b, "\n  asserted by %d surfaces: %s  ← this node is a cross-surface bridge",
			len(n.Surfaces), strings.Join(n.Surfaces, " + "))
	} else if len(n.Surfaces) == 1 {
		fmt.Fprintf(&b, "\n  surface: %s", n.Surfaces[0])
	}
	if estategraph.Crown(n) {
		b.WriteString("\n  CROWN JEWEL (sensitive data or a privileged identity)")
	}
	if n.Public {
		b.WriteString("\n  publicly reachable")
	}
	writeEdges(&b, cc.Estate, "moves FROM here", cc.Estate.Out(id), true)
	writeEdges(&b, cc.Estate, "reaches this", cc.Estate.In(id), false)
	return b.String()
}

// renderEstateChokePoints presents the highest-leverage cross-surface nodes. An empty set is a
// real answer — each attack route is separate work — not a rendering failure (§10), so it says so
// rather than promoting the least-unshared node to look decisive.
func renderEstateChokePoints(cps []estategraph.ChokePoint) string {
	if len(cps) == 0 {
		return "No cross-surface choke point: no single node sits on more than one internet→crown " +
			"route, so each path is separate work. There is no one fix that collapses several here. " +
			"(This is about CROSS-surface routes; use find_paths for cloud-only choke analysis.)"
	}
	var b strings.Builder
	b.WriteString("Highest-leverage cross-surface nodes (cutting one severs every route through it):\n")
	for _, c := range cps {
		name := c.Name
		if name == "" {
			name = c.ID
		}
		fmt.Fprintf(&b, "  - %s (%s) — on %d routes. %s\n", name, c.ID, c.Paths, c.Why)
	}
	return b.String()
}

func writeEdges(b *strings.Builder, g *estategraph.Graph, heading string, edges []estategraph.Edge, outward bool) {
	if len(edges) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s:\n", heading)
	for _, e := range edges {
		other := e.To
		if !outward {
			other = e.From
		}
		crown := ""
		if nn, ok := g.Nodes[other]; ok && estategraph.Crown(nn) {
			crown = " [CROWN]"
		}
		fmt.Fprintf(b, "  -%s-> %s%s", e.Kind, other, crown)
		if e.Why != "" {
			fmt.Fprintf(b, " — %s", e.Why)
		}
		// Evidence is printed, not summarised: the agent must be able to cite it in record_issue.
		if len(e.Evidence) > 0 {
			fmt.Fprintf(b, " (evidence: %s)", strings.Join(e.Evidence, ", "))
		}
		b.WriteString("\n")
	}
}

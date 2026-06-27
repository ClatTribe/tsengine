package cloudgraph

import (
	"strconv"

	"github.com/ClatTribe/tsengine/internal/azureiam"
	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/internal/gcpiam"
)

// prune.go closes the held-out false-positive gap the anti-overfit probe exposed: graph ingest
// over-approximates reachability by adding an assume-role edge from the inventory WITHOUT
// consulting the target role's trust policy. So the attack-path engine reported BLOCKED paths
// as real on novel trust shapes (held-out FP-reduction 0%). PruneUnauthorized re-checks each
// such edge against the policy the engine already has the evaluator for (cloudiam), and drops
// the ones the effective IAM denies — before path enumeration.

// PruneUnauthorized removes over-approximated identity edges that the effective IAM policy
// actually denies. Today it gates EdgeAssumeRole by the target role's trust policy: an edge
// (principal → role) is dropped when the role carries a trust policy (Node.Attrs["trust_policy"])
// that does NOT permit the source principal to sts:AssumeRole it.
//
// Edges with no attached policy are KEPT (today's behaviour) — absent data never prunes a
// genuinely-reachable path, so recall is preserved by construction; only edges with an explicit,
// denying policy are removed. (The permission-boundary gate on EdgePrivesc is the next increment.)
func (s *Snapshot) PruneUnauthorized() {
	if s == nil || len(s.Edges) == 0 {
		return
	}
	kept := make([]Edge, 0, len(s.Edges))
	for _, e := range s.Edges {
		if e.Kind == EdgeAssumeRole && !s.assumeAuthorized(e.From, e.To) {
			continue // trust policy denies this assume → drop the over-approximated edge
		}
		kept = append(kept, e)
	}
	if len(kept) != len(s.Edges) {
		s.Edges = kept
		s.out = nil // invalidate the lazily-built adjacency index
	}
}

// PruneUnreachable is the network twin of PruneUnauthorized — REACHABILITY PRECISION. The graph
// over-approximates an internet→resource network_reach edge from "the resource is public"; but a public
// resource whose security group only permits a corporate CIDR (or a different port) is NOT actually
// internet-reachable. This drops an internet-sourced network_reach edge when the destination's ingress
// rules DEFINITIVELY don't permit the open internet to the service port — separating theoretical exposure
// from real exposure, the category's table-stakes signal.
//
// Grounded like PruneUnauthorized: it acts only on a destination node carrying parseable
// Attrs["sg_ingress"] (a JSON []SGRule) AND a numeric Attrs["service_port"]; an edge with absent/
// unparseable rule data is KEPT (absent data never prunes a genuinely-reachable path — recall preserved).
// Optional Attrs["service_proto"] (default "tcp"). Only the internet pseudo-node source is gated; lateral
// (non-internet) reach edges are untouched here.
func (s *Snapshot) PruneUnreachable() {
	if s == nil || len(s.Edges) == 0 {
		return
	}
	kept := make([]Edge, 0, len(s.Edges))
	for _, e := range s.Edges {
		if e.Kind == EdgeNetworkReach && e.From == InternetID && s.internetBlocked(e.To) {
			continue // SG provably blocks the internet to the service port → drop the over-approximation
		}
		kept = append(kept, e)
	}
	if len(kept) != len(s.Edges) {
		s.Edges = kept
		s.out = nil
	}
}

// internetBlocked reports whether the destination node carries enough grounded config to PROVE the open
// internet cannot reach its service port. Returns false (i.e. keep the edge) whenever the data is absent
// or unparseable — only a definitive "no rule permits 0.0.0.0/0 on the port" prunes.
func (s *Snapshot) internetBlocked(dst string) bool {
	n := s.Node(dst)
	if n == nil || n.Attrs == nil {
		return false
	}
	portStr := n.Attrs["service_port"]
	if portStr == "" {
		return false // no known service port → can't disprove reachability → keep
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	rules, err := ParseSGRules(n.Attrs["sg_ingress"])
	if err != nil || len(rules) == 0 {
		return false // no parseable rules → keep (absent data never prunes)
	}
	proto := n.Attrs["service_proto"]
	if proto == "" {
		proto = "tcp"
	}
	return !InternetReachable(rules, port, proto) // rules exist and DON'T permit the internet → blocked
}

// assumeAuthorized reports whether the source principal may sts:AssumeRole the target role per
// the target's trust policy. No trust policy attached (or unparseable) ⇒ authorized, so a real
// edge is never silently dropped on missing/bad data.
func (s *Snapshot) assumeAuthorized(from, to string) bool {
	tn := s.Node(to)
	if tn == nil || tn.Attrs == nil {
		return true
	}
	// GCP: SA impersonation (the assume-role analogue) is gated by the TARGET service account's IAM policy.
	// The source must hold an impersonation permission (token-creator / actAs). Mirrors the AWS path: only a
	// DEFINITIVE deny (the policy grants the source NO impersonation perm) drops the over-approximated edge;
	// an unparseable policy or any conditional/possible grant keeps it (recall preserved, §10).
	if pol := tn.Attrs["gcp_iam_policy"]; pol != "" {
		ps, ok := gcpiam.ParseResourcePolicy([]byte(pol))
		if !ok {
			return true
		}
		member := from
		if fn := s.Node(from); fn != nil && fn.Attrs != nil && fn.Attrs["member"] != "" {
			member = fn.Attrs["member"]
		}
		for _, perm := range []string{"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.actAs"} {
			if allowed, cond := gcpiam.Permits(gcpiam.Request{Member: member, Permission: perm}, ps); allowed || cond {
				return true
			}
		}
		return false
	}
	// Azure: the assume/escalate analogue is "can the source take control of the target identity/scope?" —
	// gated by the target's attached RBAC policy. We test a representative privileged action (assign a role
	// on the target = escalate to own it); definitively not granted → drop the over-approximated edge. Same
	// conservatism as the AWS/GCP paths (unparseable/uncertain → keep).
	if pol := tn.Attrs["azure_rbac_policy"]; pol != "" {
		ps, ok := azureiam.ParseScopePolicy([]byte(pol))
		if !ok {
			return true
		}
		principal := from
		if fn := s.Node(from); fn != nil && fn.Attrs != nil && fn.Attrs["principal"] != "" {
			principal = fn.Attrs["principal"]
		}
		for _, act := range []string{"Microsoft.Authorization/roleAssignments/write", "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"} {
			if allowed, cond := azureiam.Permits(azureiam.Request{Principal: principal, Action: act}, ps); allowed || cond {
				return true
			}
		}
		return false
	}
	raw := tn.Attrs["trust_policy"]
	if raw == "" {
		return true
	}
	doc, err := cloudiam.Parse([]byte(raw))
	if err != nil {
		return true
	}
	principal := from
	if fn := s.Node(from); fn != nil && fn.Attrs != nil && fn.Attrs["arn"] != "" {
		principal = fn.Attrs["arn"]
	}
	allowed, _ := cloudiam.Allows("sts:AssumeRole", principal, doc)
	return allowed
}

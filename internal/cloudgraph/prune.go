package cloudgraph

import "github.com/ClatTribe/tsengine/internal/cloudiam"

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

// assumeAuthorized reports whether the source principal may sts:AssumeRole the target role per
// the target's trust policy. No trust policy attached (or unparseable) ⇒ authorized, so a real
// edge is never silently dropped on missing/bad data.
func (s *Snapshot) assumeAuthorized(from, to string) bool {
	tn := s.Node(to)
	if tn == nil || tn.Attrs == nil {
		return true
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

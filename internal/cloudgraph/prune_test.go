package cloudgraph

import "testing"

func hasEdge(s *Snapshot, from, to string, k EdgeKind) bool {
	for _, e := range s.Edges {
		if e.From == from && e.To == to && e.Kind == k {
			return true
		}
	}
	return false
}

func TestPruneUnauthorized_AssumeRoleTrustGate(t *testing.T) {
	const srcArn = "arn:aws:iam::111111111111:role/src"
	// priv-role trusts ONLY someone-else, NOT src.
	denyTrust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::111111111111:role/someone-else"}]}`
	allowTrust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"` + srcArn + `"}]}`

	build := func(trust string) *Snapshot {
		s := New("acct", "aws")
		s.AddNode(&Node{ID: "src", Kind: KindPrincipal, Attrs: map[string]string{"arn": srcArn}})
		attrs := map[string]string{}
		if trust != "" {
			attrs["trust_policy"] = trust
		}
		s.AddNode(&Node{ID: "priv", Kind: KindPrincipal, Attrs: attrs})
		s.AddEdge(Edge{From: "src", To: "priv", Kind: EdgeAssumeRole})
		return s
	}

	// 1. Denying trust policy → the over-approximated assume edge is pruned.
	deny := build(denyTrust)
	deny.PruneUnauthorized()
	if hasEdge(deny, "src", "priv", EdgeAssumeRole) {
		t.Error("assume edge denied by the trust policy must be pruned")
	}

	// 2. No trust policy attached → edge kept (recall preserved; absent data never prunes).
	none := build("")
	none.PruneUnauthorized()
	if !hasEdge(none, "src", "priv", EdgeAssumeRole) {
		t.Error("assume edge with no trust policy must be kept")
	}

	// 3. Allowing trust policy → edge kept.
	allow := build(allowTrust)
	allow.PruneUnauthorized()
	if !hasEdge(allow, "src", "priv", EdgeAssumeRole) {
		t.Error("assume edge permitted by the trust policy must be kept")
	}
}

package cloudgraph

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

func mustDoc(t *testing.T, js string) *cloudiam.Document {
	t.Helper()
	d, err := cloudiam.Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A permission boundary is a CEILING. A role whose attached policy allows an escalation
// its boundary does not permit cannot escalate, and AWS says so — effective = attached ∧
// boundary.
//
// This was measured, not theorised: the held-out generalization benchmark scored 50% on
// shapes the engine does not encode and named this one. A false attack path is worse than
// a missed one here — it sends someone to sever a route that was never open, with the
// confidence of a rendered graph, while the real one stays open.
func TestAddPrivescEdgesWithBoundaries_BoundaryBlocksTheEscalation(t *testing.T) {
	attached := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicyVersion"],"Resource":"*"}]}`)
	boundary := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":["s3:Get*"],"Resource":"*"}]}`)

	s := New("123456789012", "aws")
	s.AddNode(&Node{ID: "role", Kind: KindPrincipal, Type: "iam_role", Name: "role"})
	s.AddPrivescEdgesWithBoundaries(map[string]PrincipalPolicies{
		"role": {Identity: []*cloudiam.Document{attached}, Boundary: boundary},
	})

	for _, e := range s.Edges {
		if e.Kind == EdgePrivesc && e.From == "role" {
			t.Fatalf("the boundary permits only s3:Get* — this escalation is blocked, and reporting "+
				"it is a false path to admin: %+v", e)
		}
	}
	if s.Node(AdminID) != nil {
		t.Fatal("no principal can escalate, so the synthetic admin node should not have been created")
	}
}

// The other direction must still work: a boundary that PERMITS the escalation leaves the
// edge in place. A fix that closed the gap by dropping real paths would be worse than the
// bug it fixed.
func TestAddPrivescEdgesWithBoundaries_PermissiveBoundaryKeepsTheEdge(t *testing.T) {
	attached := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicyVersion"],"Resource":"*"}]}`)
	boundary := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*"}]}`)

	s := New("123456789012", "aws")
	s.AddNode(&Node{ID: "role", Kind: KindPrincipal, Type: "iam_role", Name: "role"})
	s.AddPrivescEdgesWithBoundaries(map[string]PrincipalPolicies{
		"role": {Identity: []*cloudiam.Document{attached}, Boundary: boundary},
	})

	var found bool
	for _, e := range s.Edges {
		if e.Kind == EdgePrivesc && e.From == "role" {
			found = true
		}
	}
	if !found {
		t.Fatal("the boundary permits everything, so the escalation is real and must still be reported")
	}
}

// NO boundary and an EMPTY boundary are different facts, and the distinction is the
// reason PrincipalPolicies.Boundary is a pointer. A principal with no boundary is
// unconstrained; treating "we have no boundary data" as "the boundary allows nothing"
// would silently delete every privesc edge in an account we simply have not read.
func TestAddPrivescEdgesWithBoundaries_NoBoundaryIsNotAnEmptyBoundary(t *testing.T) {
	attached := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicyVersion"],"Resource":"*"}]}`)

	s := New("123456789012", "aws")
	s.AddNode(&Node{ID: "role", Kind: KindPrincipal, Type: "iam_role", Name: "role"})
	s.AddPrivescEdgesWithBoundaries(map[string]PrincipalPolicies{
		"role": {Identity: []*cloudiam.Document{attached}}, // Boundary nil
	})

	var found bool
	for _, e := range s.Edges {
		if e.Kind == EdgePrivesc {
			found = true
		}
	}
	if !found {
		t.Fatal("a principal with no permission boundary is unconstrained by one — absence of " +
			"boundary data must never read as a boundary that denies everything")
	}
}

// The legacy entry point must behave exactly as it did, so a caller that genuinely has no
// boundary data is unaffected.
func TestAddPrivescEdges_LegacyEntryPointUnchanged(t *testing.T) {
	attached := mustDoc(t, `{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicyVersion"],"Resource":"*"}]}`)

	s := New("123456789012", "aws")
	s.AddNode(&Node{ID: "role", Kind: KindPrincipal, Type: "iam_role", Name: "role"})
	s.AddPrivescEdges(map[string][]*cloudiam.Document{"role": {attached}})

	var found bool
	for _, e := range s.Edges {
		if e.Kind == EdgePrivesc {
			found = true
		}
	}
	if !found {
		t.Fatal("the boundary-unaware path must keep working for callers with no boundary data")
	}
}

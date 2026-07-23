package cloudagent

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

func shownNames(cc *Context) map[string]bool {
	m := map[string]bool{}
	for _, t := range selectTools(cc) {
		m[t.name] = true
	}
	return m
}

// TestSelectTools_FixGatedOnIssue: propose_fix is hidden until an issue is recorded; the cohesive analysis
// tools always show.
func TestSelectTools_FixGatedOnIssue(t *testing.T) {
	s := cloudgraph.New("acct", "aws")
	cc := &Context{Snap: s}
	m := shownNames(cc)
	if m["propose_fix"] {
		t.Error("propose_fix must be hidden with no recorded issue")
	}
	for _, want := range []string{"list_resources", "resolve_access", "find_paths", "blast_radius", "detect_privesc", "record_issue", "finish"} {
		if !m[want] {
			t.Errorf("the cohesive reasoner tool %q must always show", want)
		}
	}
	// after an issue is recorded, propose_fix appears
	cc.Issues = []Issue{{}}
	if !shownNames(cc)["propose_fix"] {
		t.Error("propose_fix must appear once an issue is recorded")
	}
}

// TestSelectTools_RightsizeGatedOnUsage: rightsize_principal shows only when a principal carries usage data.
func TestSelectTools_RightsizeGatedOnUsage(t *testing.T) {
	s := cloudgraph.New("acct", "aws")
	s.AddNode(&cloudgraph.Node{ID: "p", Kind: cloudgraph.KindPrincipal}) // no usage data
	if shownNames(&Context{Snap: s})["rightsize_principal"] {
		t.Error("rightsize_principal must be hidden without usage data (it would no-op)")
	}
	s.AddNode(&cloudgraph.Node{ID: "q", Kind: cloudgraph.KindPrincipal, Attrs: map[string]string{"usage_observed": "true"}})
	if !shownNames(&Context{Snap: s})["rightsize_principal"] {
		t.Error("rightsize_principal must show when usage data is present")
	}
}

// TestSelectTools_DispatchIsFull: every tool stays in the dispatch catalog (disclosure never removes capability).
func TestSelectTools_DispatchIsFull(t *testing.T) {
	all := map[string]bool{}
	for _, td := range tools() {
		all[td.name] = true
	}
	for _, must := range []string{"propose_fix", "rightsize_principal"} {
		if !all[must] {
			t.Errorf("dispatch catalog must always contain %q", must)
		}
	}
}

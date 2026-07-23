package webagent

import (
	"strings"
	"testing"
)

// TestWorldModel_CrossHostPivot (P3): a leaked-cred SSH hop after HTTP discovery adds the SSH host and a
// pivot edge web-host → ssh-host (the XBEN-042 lateral-movement chain), surfaced in the digest.
func TestWorldModel_CrossHostPivot(t *testing.T) {
	turns := []Turn{
		{ID: "t-1", Method: "GET", URL: "https://app.acme.com/config", Status: 200}, // web host discovered first
		{ID: "t-2", Method: "ssh_exec", URL: "pedro@10.0.0.5:22", Status: 200, RespSnippet: "flag{...}"},
	}
	w := BuildWorldModel(turns, nil)

	// both hosts present, with the right services
	if h := w.Hosts["10.0.0.5:22"]; h == nil || !contains(h.Services, "ssh") {
		t.Fatalf("the SSH host must be modeled with an ssh service: %+v", w.Hosts)
	}
	if h := w.Hosts["app.acme.com"]; h == nil || !contains(h.Services, "https") {
		t.Fatalf("the web host must carry https: %+v", w.Hosts)
	}
	// exactly one pivot edge, web → ssh, via leaked-cred
	if len(w.Edges) != 1 {
		t.Fatalf("want 1 pivot edge, got %d: %+v", len(w.Edges), w.Edges)
	}
	e := w.Edges[0]
	if e.FromHost != "app.acme.com" || e.ToHost != "10.0.0.5:22" || e.Via != "leaked-cred" {
		t.Errorf("wrong pivot edge: %+v", e)
	}
	// digest renders the pivot
	if d := w.Digest(); !strings.Contains(d, "PIVOT app.acme.com -> 10.0.0.5:22") {
		t.Errorf("digest must render the pivot: %q", d)
	}
}

// TestWorldModel_PivotDedup: repeated hops to the same host don't multiply the edge.
func TestWorldModel_PivotDedup(t *testing.T) {
	turns := []Turn{
		{ID: "t-1", Method: "GET", URL: "https://app.acme.com/", Status: 200},
		{ID: "t-2", Method: "ssh_exec", URL: "u@10.0.0.5:22", Status: 200},
		{ID: "t-3", Method: "ssh_exec", URL: "u@10.0.0.5:22", Status: 200},
	}
	if w := BuildWorldModel(turns, nil); len(w.Edges) != 1 {
		t.Errorf("repeated hops must not duplicate the edge, got %d", len(w.Edges))
	}
}

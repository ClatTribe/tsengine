package ip

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/httpx"
	_ "github.com/ClatTribe/tsengine/internal/tool/naabu"
	_ "github.com/ClatTribe/tsengine/internal/tool/nmap"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
)

func TestHandler_TypeAndAnchors(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetIPAddress {
		t.Errorf("Type: %q", h.Type())
	}
	got := map[string]bool{}
	for _, a := range h.Anchors() {
		got[a.Name()] = true
	}
	for _, want := range []string{"nmap", "httpx"} {
		if !got[want] {
			t.Errorf("missing anchor %q (got %v)", want, got)
		}
	}
}

func TestPlanAnchors_PassesTarget(t *testing.T) {
	h := NewHandler()
	out := h.PlanAnchors(types.Asset{Type: types.AssetIPAddress, Target: "10.0.0.0/24"})
	if len(out) != 2 {
		t.Fatalf("dispatches: %d, want 2", len(out))
	}
	for _, d := range out {
		if d.Args["target"] != "10.0.0.0/24" {
			t.Errorf("%s target: %v", d.Tool.Name(), d.Args["target"])
		}
	}
}

func TestRecon_OffersNaabu(t *testing.T) {
	if len(NewHandler().Recon()) != 1 {
		t.Fatal("Recon() should offer naabu when registered")
	}
}

// PlanFanout over a discovered host:port surface: nmap gets the port list,
// httpx probes only HTTP-like ports, nuclei runs per-port with routed tags.
func TestPlanFanout_PerPortRouting(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetIPAddress, Target: "10.0.0.5"}
	surface := []string{"10.0.0.5", "10.0.0.5:22", "10.0.0.5:443", "10.0.0.5:3306"}
	out := h.PlanFanout(target, surface)

	byTool := map[string]int{}
	nucleiTags := map[string]string{}
	var nmapPorts, httpxTargets string
	for _, d := range out {
		byTool[d.Tool.Name()]++
		switch d.Tool.Name() {
		case "nuclei":
			nucleiTags[d.Args["target"].(string)] = d.Args["tags"].(string)
		case "nmap":
			nmapPorts, _ = d.Args["ports"].(string)
		case "httpx":
			httpxTargets, _ = d.Args["targets"].(string)
		}
	}

	if byTool["nmap"] != 1 {
		t.Errorf("nmap: got %d, want 1", byTool["nmap"])
	}
	if nmapPorts != "22,443,3306" {
		t.Errorf("nmap ports = %q, want 22,443,3306 (sorted discovered)", nmapPorts)
	}
	if byTool["nuclei"] != 3 {
		t.Errorf("nuclei: got %d, want 3 (per-port)", byTool["nuclei"])
	}
	if got := nucleiTags["10.0.0.5:22"]; got != "ssh,openssh" {
		t.Errorf("port 22 tags = %q, want ssh,openssh", got)
	}
	if got := nucleiTags["10.0.0.5:3306"]; got != "mysql" {
		t.Errorf("port 3306 tags = %q, want mysql", got)
	}
	if byTool["httpx"] != 1 {
		t.Errorf("httpx: got %d, want 1", byTool["httpx"])
	}
	if httpxTargets != "10.0.0.5:443" {
		t.Errorf("httpx targets = %q, want only the HTTP-like port", httpxTargets)
	}
}

// Recon-empty fallback: surface is just the bare target → nmap + httpx on
// the target, no per-port nuclei (pre-A1 behavior, no regression).
func TestPlanFanout_BareTargetFallback(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetIPAddress, Target: "10.0.0.5"}
	out := h.PlanFanout(target, []string{"10.0.0.5"})

	byTool := map[string]int{}
	for _, d := range out {
		byTool[d.Tool.Name()]++
		if d.Tool.Name() == "nmap" {
			if _, hasPorts := d.Args["ports"]; hasPorts {
				t.Error("nmap should use default ports when recon found none")
			}
		}
	}
	if byTool["nmap"] != 1 || byTool["httpx"] != 1 {
		t.Errorf("fallback want nmap+httpx on target, got %v", byTool)
	}
	if byTool["nuclei"] != 0 {
		t.Errorf("no per-port nuclei without discovered ports, got %d", byTool["nuclei"])
	}
}

func TestNucleiTagsForPort_DefaultsToNetwork(t *testing.T) {
	if got := nucleiTagsForPort(12345); got != "network" {
		t.Errorf("unknown port tags = %q, want network", got)
	}
}

func TestSplitHostPort(t *testing.T) {
	if _, p, ok := splitHostPort("1.2.3.4:8080"); !ok || p != 8080 {
		t.Errorf("splitHostPort host:port failed: p=%d ok=%v", p, ok)
	}
	if _, _, ok := splitHostPort("1.2.3.4"); ok {
		t.Error("bare host should report ok=false")
	}
}

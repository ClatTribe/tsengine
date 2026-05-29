package domain

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/amass"
	_ "github.com/ClatTribe/tsengine/internal/tool/checkdmarc"
	_ "github.com/ClatTribe/tsengine/internal/tool/crtsh"
	_ "github.com/ClatTribe/tsengine/internal/tool/httpx"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	_ "github.com/ClatTribe/tsengine/internal/tool/subfinder"
)

func TestHandler_TypeAndAnchors(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetDomain {
		t.Errorf("Type: %q", h.Type())
	}
	if len(h.Anchors()) != 1 || h.Anchors()[0].Name() != "subfinder" {
		t.Errorf("Anchors: %v", h.Anchors())
	}
}

func TestPlanAnchors_NormalizesToApex(t *testing.T) {
	h := NewHandler()
	cases := map[string]string{
		"https://www.example.com/path":  "www.example.com",
		"example.com":                   "example.com",
		"http://api.example.com:8080/x": "api.example.com",
		"EXAMPLE.COM":                   "example.com",
	}
	for in, want := range cases {
		out := h.PlanAnchors(types.Asset{Type: types.AssetDomain, Target: in})
		if len(out) != 1 {
			t.Fatalf("dispatches: %d", len(out))
		}
		if got := out[0].Args["target"]; got != want {
			t.Errorf("apex(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestRecon_OffersThreeSources(t *testing.T) {
	if got := len(NewHandler().Recon()); got != 3 {
		t.Errorf("Recon() = %d sources, want 3 (subfinder+amass+crtsh)", got)
	}
}

func TestPlanRecon_PassesApex(t *testing.T) {
	out := NewHandler().PlanRecon(types.Asset{Type: types.AssetDomain, Target: "https://x.example.com/p"})
	if len(out) != 3 {
		t.Fatalf("PlanRecon dispatches = %d, want 3", len(out))
	}
	for _, d := range out {
		if d.Args["target"] != "x.example.com" {
			t.Errorf("%s recon target = %v, want apex", d.Tool.Name(), d.Args["target"])
		}
	}
}

func TestPlanFanout_DNSHealthTakeoverHTTP(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetDomain, Target: "example.com"}
	surface := []string{"example.com", "a.example.com", "b.example.com"}
	out := h.PlanFanout(target, surface)

	byTool := map[string]int{}
	var nucleiTags, cdTarget string
	for _, d := range out {
		byTool[d.Tool.Name()]++
		switch d.Tool.Name() {
		case "nuclei":
			nucleiTags, _ = d.Args["tags"].(string)
		case "checkdmarc":
			cdTarget, _ = d.Args["target"].(string)
		}
	}
	if byTool["checkdmarc"] != 1 || cdTarget != "example.com" {
		t.Errorf("checkdmarc should run once on the apex; got %d target=%q", byTool["checkdmarc"], cdTarget)
	}
	if byTool["nuclei"] != 1 || nucleiTags != "takeover" {
		t.Errorf("nuclei should run once with takeover tags; got %d tags=%q", byTool["nuclei"], nucleiTags)
	}
	if byTool["httpx"] != 1 {
		t.Errorf("httpx should run once (list mode); got %d", byTool["httpx"])
	}
}

func TestChildAssets_FromSubdomainFindings(t *testing.T) {
	h := NewHandler()
	findings := []types.Finding{
		{RuleID: "subfinder::subdomain-found", Tool: "subfinder", Endpoint: "a.example.com"},
		{RuleID: "crtsh::subdomain-found", Tool: "crtsh", Endpoint: "a.example.com"}, // dup host
		{RuleID: "amass::subdomain-found", Tool: "amass", Endpoint: "b.example.com"},
		{RuleID: "checkdmarc::dmarc-policy-none", Tool: "checkdmarc", Endpoint: "example.com"}, // not a subdomain
	}
	kids := h.ChildAssets(findings)
	if len(kids) != 2 {
		t.Fatalf("child assets = %d, want 2 (deduped, subdomain-only)", len(kids))
	}
	for _, c := range kids {
		if c.AssetType != types.AssetWebApplication {
			t.Errorf("child %q type = %q, want web_application", c.Host, c.AssetType)
		}
	}
}

package l2

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// --- mocks for the external-service seams ---------------------------------

type mockTI struct{ summary string }

func (m mockTI) LookupCVE(_ context.Context, cve string) (string, bool) {
	if m.summary == "" {
		return "", false
	}
	return m.summary + " [" + cve + "]", true
}

type mockCompliance struct{ summary string }

func (m mockCompliance) MapCWE(_ []string) string { return m.summary }

type mockProber struct {
	summary string
	err     error
	gotTool string
	gotArgs map[string]any
}

func (m *mockProber) Probe(_ context.Context, tool string, args map[string]any) (string, error) {
	m.gotTool, m.gotArgs = tool, args
	return m.summary, m.err
}

type mockHTTP struct {
	summary           string
	err               error
	gotMethod, gotURL string
	gotHeaders        map[string]string
}

func (m *mockHTTP) Do(_ context.Context, method, url string, headers map[string]string, _ string) (string, error) {
	m.gotMethod, m.gotURL, m.gotHeaders = method, url, headers
	return m.summary, m.err
}

// wiredDeps wires every external service — the full-width (~10-tool) catalog.
func wiredDeps() Deps {
	return Deps{
		Target:      webTarget(),
		L1Findings:  sampleFindings(),
		ThreatIntel: mockTI{summary: "CVSS 10.0, KEV listed, EPSS 0.97"},
		Compliance:  mockCompliance{summary: "SOC2 CC6.1; PCI 6.2.4"},
		Prober:      &mockProber{summary: "sqlmap: parameter id is injectable (boolean-based)"},
		HTTP:        &mockHTTP{summary: "200 OK; payload reflected in body"},
	}
}

func TestExternalTools_OmittedWhenServiceNil(t *testing.T) {
	// No services wired → none of the four external tools appear.
	c := BuildCatalog(Deps{L1Findings: sampleFindings()})
	for _, name := range []string{"query_threat_intel", "lookup_compliance_mapping", "dispatch_l2_probe", "send_request"} {
		if _, ok := c.find(name); ok {
			t.Errorf("%q should be absent when its service is nil", name)
		}
	}
}

func TestExternalTools_PresentAndUnderCapWhenWired(t *testing.T) {
	c := BuildCatalog(wiredDeps())
	if err := c.Validate(); err != nil {
		t.Fatalf("full-width catalog must satisfy the ≤%d cap: %v", MaxCatalog, err)
	}
	for _, name := range []string{"query_threat_intel", "lookup_compliance_mapping", "dispatch_l2_probe", "send_request"} {
		if _, ok := c.find(name); !ok {
			t.Errorf("%q should be present when wired", name)
		}
	}
}

func TestQueryThreatIntel(t *testing.T) {
	c := BuildCatalog(wiredDeps())
	tool, _ := c.find("query_threat_intel")
	res, err := tool.Handler(context.Background(), map[string]any{"cve": "CVE-2021-44228"}, &State{})
	if err != nil || res.Err {
		t.Fatalf("lookup failed: %v %q", err, res.Content)
	}
	if !strings.Contains(res.Content, "KEV listed") || !strings.Contains(res.Content, "CVE-2021-44228") {
		t.Errorf("unexpected summary: %q", res.Content)
	}

	// Not-found CVE → error result.
	cNF := BuildCatalog(Deps{L1Findings: sampleFindings(), ThreatIntel: mockTI{}})
	tNF, _ := cNF.find("query_threat_intel")
	if res, _ := tNF.Handler(context.Background(), map[string]any{"cve": "CVE-0000-0000"}, &State{}); !res.Err {
		t.Error("unknown CVE should return an error result")
	}
}

func TestDispatchL2Probe_PassesToolAndArgs(t *testing.T) {
	pr := &mockProber{summary: "injectable"}
	c := BuildCatalog(Deps{L1Findings: sampleFindings(), Prober: pr})
	tool, _ := c.find("dispatch_l2_probe")
	res, err := tool.Handler(context.Background(), map[string]any{
		"tool": "sqlmap",
		"args": map[string]any{"url": "https://x/p?id=1", "level": "3"},
	}, &State{})
	if err != nil || res.Err {
		t.Fatalf("probe failed: %v %q", err, res.Content)
	}
	if pr.gotTool != "sqlmap" || pr.gotArgs["url"] != "https://x/p?id=1" {
		t.Errorf("probe got tool=%q args=%v", pr.gotTool, pr.gotArgs)
	}

	// Probe error surfaces as an error result, not a Go error.
	prErr := &mockProber{err: errors.New("replay 500")}
	cErr := BuildCatalog(Deps{Prober: prErr})
	tErr, _ := cErr.find("dispatch_l2_probe")
	if res, err := tErr.Handler(context.Background(), map[string]any{"tool": "sqlmap"}, &State{}); err != nil || !res.Err {
		t.Errorf("probe error should be an error RESULT: err=%v res=%+v", err, res)
	}
}

func TestSendRequest_DefaultsMethodAndPassesHeaders(t *testing.T) {
	hc := &mockHTTP{summary: "200 OK"}
	c := BuildCatalog(Deps{HTTP: hc})
	tool, _ := c.find("send_request")
	res, err := tool.Handler(context.Background(), map[string]any{
		"url":     "https://x/echo?q=<script>",
		"headers": map[string]any{"Cookie": "sid=abc"},
	}, &State{})
	if err != nil || res.Err {
		t.Fatalf("send_request failed: %v %q", err, res.Content)
	}
	if hc.gotMethod != "GET" {
		t.Errorf("method should default to GET, got %q", hc.gotMethod)
	}
	if hc.gotHeaders["Cookie"] != "sid=abc" {
		t.Errorf("headers not passed: %v", hc.gotHeaders)
	}

	// Missing url → error result.
	if res, _ := tool.Handler(context.Background(), map[string]any{}, &State{}); !res.Err {
		t.Error("missing url should return an error result")
	}
}

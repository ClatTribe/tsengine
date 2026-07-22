package execpolicy

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

// TestAllow_NilIsPermissive: no policy → back-compat (dev). The production spawn path always sets one.
func TestAllow_NilIsPermissive(t *testing.T) {
	var p *Policy
	if err := p.Allow("sqlmap", map[string]any{"target": "http://internal"}, 999, t0); err != nil {
		t.Errorf("nil policy must be permissive, got %v", err)
	}
}

// TestAllow_ToolPinning: only listed tools run when Tools is set.
func TestAllow_ToolPinning(t *testing.T) {
	p := &Policy{Tools: []string{"nuclei", "httpx"}}
	if err := p.Allow("nuclei", nil, 0, t0); err != nil {
		t.Errorf("in-policy tool must run: %v", err)
	}
	if err := p.Allow("sqlmap", nil, 0, t0); err == nil {
		t.Error("a tool NOT in the policy must be refused (a miswired/compromised orchestrator can't widen it)")
	}
}

// TestAllow_HostScope: targets must be within the authorized hosts — the core "can't attack an
// internal host it was never scoped to" property. Covers url / bare host / []string / []any shapes.
func TestAllow_HostScope(t *testing.T) {
	p := &Policy{Hosts: []string{"app.acme.com"}}
	ok := []map[string]any{
		{"target": "https://app.acme.com/login"},
		{"url": "http://app.acme.com:8080/x"},
		{"host": "app.acme.com:443"},
		{"targets": []string{"https://app.acme.com/a", "https://app.acme.com/b"}},
		{"urls": []any{"https://app.acme.com/c"}},
	}
	for i, a := range ok {
		if err := p.Allow("nuclei", a, 0, t0); err != nil {
			t.Errorf("in-scope args[%d] must pass: %v", i, err)
		}
	}
	bad := []map[string]any{
		{"target": "http://169.254.169.254/latest/meta-data/"}, // the metadata escape
		{"target": "https://internal-db.acme.local/"},
		{"targets": []string{"https://app.acme.com/a", "https://evil.example.com/"}}, // one off-scope in a list
		{"host": "10.0.0.5:22"},
	}
	for i, a := range bad {
		if err := p.Allow("nuclei", a, 0, t0); err == nil {
			t.Errorf("off-scope args[%d] MUST be refused: %v", i, a)
		}
	}
}

// TestAllow_Budget: the per-container run budget is enforced.
func TestAllow_Budget(t *testing.T) {
	p := &Policy{MaxRequests: 3}
	for c := 0; c < 3; c++ {
		if err := p.Allow("nuclei", nil, c, t0); err != nil {
			t.Errorf("run %d within budget must pass: %v", c, err)
		}
	}
	if err := p.Allow("nuclei", nil, 3, t0); err == nil {
		t.Error("exceeding the budget must be refused")
	}
}

// TestAllow_Expiry: a stale capability is refused (bounds the window a leaked policy is usable).
func TestAllow_Expiry(t *testing.T) {
	p := &Policy{NotAfter: t0.Add(time.Hour)}
	if err := p.Allow("nuclei", nil, 0, t0); err != nil {
		t.Errorf("before expiry must pass: %v", err)
	}
	if err := p.Allow("nuclei", nil, 0, t0.Add(2*time.Hour)); err == nil {
		t.Error("after expiry must be refused")
	}
}

// TestAllow_EmptyDimensionsUnconstrained: {MaxRequests:200} bounds volume but not tools/targets.
func TestAllow_EmptyDimensionsUnconstrained(t *testing.T) {
	p := &Policy{MaxRequests: 200}
	if err := p.Allow("anytool", map[string]any{"target": "http://anywhere"}, 0, t0); err != nil {
		t.Errorf("unconstrained tool/host must pass: %v", err)
	}
}

// TestFromEnv: empty → nil (permissive); valid JSON round-trips; malformed is a LOUD error.
func TestFromEnv(t *testing.T) {
	if p, err := FromEnv(""); err != nil || p != nil {
		t.Errorf("empty → (nil,nil), got (%v,%v)", p, err)
	}
	src := &Policy{Tools: []string{"nuclei"}, Hosts: []string{"a.com"}, MaxRequests: 5, NotAfter: t0}
	enc, err := src.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromEnv(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tools) != 1 || got.Tools[0] != "nuclei" || got.MaxRequests != 5 || !got.NotAfter.Equal(t0) {
		t.Errorf("round-trip wrong: %+v", got)
	}
	if _, err := FromEnv("{not json"); err == nil {
		t.Error("malformed policy must be a LOUD error, never a silent permissive fallback")
	}
}

func TestHostsFromArgs_IPv6AndDedup(t *testing.T) {
	got := HostsFromArgs(map[string]any{"url": "http://[::1]:8080/x", "target": "http://app.acme.com", "targets": []string{"http://app.acme.com/y"}})
	// ::1 + app.acme.com, deduped
	seen := map[string]bool{}
	for _, h := range got {
		seen[h] = true
	}
	if !seen["::1"] || !seen["app.acme.com"] {
		t.Errorf("want ::1 + app.acme.com, got %v", got)
	}
	if len(got) != 2 {
		t.Errorf("app.acme.com must dedupe across keys, got %v", got)
	}
}

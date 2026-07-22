package netguard

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestIsPublicIP(t *testing.T) {
	block := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", // loopback + RFC1918
		"169.254.169.254", "100.64.0.1", "203.0.113.5", "198.51.100.7", "192.0.2.1", "240.0.0.1", // link-local + special-use
		"::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1", "2001:db8::1", // IPv6 loopback/ULA/link-local/mapped-private/doc
	}
	for _, s := range block {
		if IsPublicIP(net.ParseIP(s)) {
			t.Errorf("IsPublicIP(%s) = true, want false (SSRF guard must refuse it)", s)
		}
	}
	allow := []string{"8.8.8.8", "1.1.1.1", "203.0.114.9", "2606:4700:4700::1111", "::ffff:8.8.8.8"}
	for _, s := range allow {
		if !IsPublicIP(net.ParseIP(s)) {
			t.Errorf("IsPublicIP(%s) = false, want true (a routable public address)", s)
		}
	}
}

func TestGuardedDialContext_RefusesNonPublic(t *testing.T) {
	dial := GuardedDialContext(2 * time.Second)
	// Loopback / metadata must be refused BY THE SCREEN — no real connection is attempted.
	if _, err := dial(context.Background(), "tcp", "127.0.0.1:80"); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Errorf("dial to loopback must be refused with a non-public error, got %v", err)
	}
	if _, err := dial(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Error("dial to the cloud metadata IP must be refused")
	}
}

// TestIsForbiddenIP pins the offensive-agent egress policy: metadata + loopback + link-local are
// NEVER reachable (the SSRF-escalation surface), but private/RFC1918 IS permitted (an authorized
// internal pentest target). This split is the whole reason it's separate from IsPublicIP.
func TestIsForbiddenIP(t *testing.T) {
	forbidden := []string{
		"169.254.169.254",  // AWS/GCP/Azure IMDS — the credential-theft address
		"169.254.170.2",    // ECS task metadata
		"fd00:ec2::254",    // IPv6 IMDS (unique-local — the case IsPrivate would wrongly permit)
		"127.0.0.1", "::1", // loopback → the platform host itself
		"169.254.10.20", // link-local generally
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", "ff02::1", // multicast
	}
	for _, s := range forbidden {
		if !IsForbiddenIP(net.ParseIP(s)) {
			t.Errorf("MUST be forbidden for an offensive agent: %s", s)
		}
	}
	if !IsForbiddenIP(nil) {
		t.Error("nil IP must be forbidden (fail closed)")
	}
	// PERMITTED — a pentest may legitimately target these; scope (not this guard) gates them.
	permitted := []string{"8.8.8.8", "1.1.1.1", "10.0.0.1", "172.16.0.1", "192.168.1.10", "2606:4700:4700::1111"}
	for _, s := range permitted {
		if IsForbiddenIP(net.ParseIP(s)) {
			t.Errorf("must be PERMITTED (public or in-scope-private): %s", s)
		}
	}
}

// fakeResolver resolves any host to a fixed IP — so the metadata-rebind defense can be tested
// deterministically (no real DNS that resolves an in-scope name to 169.254.169.254).
type fakeResolver struct{ ip string }

func (f fakeResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP(f.ip)}}, nil
}

// TestForbiddenDial_BlocksMetadataAlways is the core containment invariant: an in-scope hostname that
// RESOLVES (or rebinds) to the cloud-metadata address is refused at dial time, and onDeny fires — even
// with allowLoopback set. This is the exact SSRF→169.254.169.254→instance-creds path from the incident.
func TestForbiddenDial_BlocksMetadataAlways(t *testing.T) {
	for _, allowLoopback := range []bool{false, true} {
		var denied string
		dc := forbiddenDialWith(fakeResolver{"169.254.169.254"}, time.Second, allowLoopback,
			func(host string, ip net.IP) { denied = host + "→" + ip.String() })
		_, err := dc(context.Background(), "tcp", "target.example.com:80")
		if err == nil || !strings.Contains(err.Error(), "metadata") {
			t.Errorf("allowLoopback=%v: a host rebinding to metadata must be refused, got: %v", allowLoopback, err)
		}
		if denied == "" {
			t.Errorf("allowLoopback=%v: onDeny must fire (the circuit-breaker signal)", allowLoopback)
		}
	}
}

// TestForbiddenDial_LoopbackPolicy: loopback is refused in strict mode but permitted when the caller
// (the host-side offensive agent, with scope-gated local targets) sets allowLoopback.
func TestForbiddenDial_LoopbackPolicy(t *testing.T) {
	strict := forbiddenDialWith(fakeResolver{"127.0.0.1"}, time.Second, false, nil)
	if _, err := strict(context.Background(), "tcp", "x:80"); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("strict mode must refuse loopback, got: %v", err)
	}
	// permissive: loopback passes the guard (the dial then fails to a closed port, but that is NOT a
	// guard rejection) — assert onDeny never fired.
	fired := false
	permissive := forbiddenDialWith(fakeResolver{"127.0.0.1"}, 200*time.Millisecond, true, func(string, net.IP) { fired = true })
	_, _ = permissive(context.Background(), "tcp", "127.0.0.1:9") // discard port; connect fails, guard doesn't reject
	if fired {
		t.Error("allowLoopback must let loopback through the guard (no onDeny)")
	}
}

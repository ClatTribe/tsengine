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

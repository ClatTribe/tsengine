// Package netguard is the single source of truth for the platform's SSRF guard: an IP allowlist that
// admits only routable public addresses, plus an http.Transport DialContext that resolves a host,
// refuses any non-public address, and dials the validated IP (no DNS-rebind window). Centralizing it
// means the public /v1/assess prober and the L2 agent's host-side send_request primitive screen with
// the EXACT same rules and can never drift apart.
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// GuardedClient returns an http.Client whose transport refuses to connect to any non-public host (the
// SSRF guard) and is bounded by timeout. Use it for every outbound request to an operator- or
// tenant-configurable base URL, so a URL pointed at an internal/loopback/metadata address can't be
// reached server-side. Tests that must hit a loopback httptest server inject their own *http.Client.
func GuardedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: GuardedDialContext(timeout), DisableKeepAlives: true},
	}
}

// nonPublicCIDRs are special-use / non-routable ranges the stdlib predicates (IsPrivate/IsLoopback/…)
// do NOT cover but an SSRF guard must still refuse. CGNAT (RFC 6598) is the headline — cloud providers
// run internal proxies + metadata-adjacent infra there — and the IPv6 NAT64/6to4 ranges embed an IPv4
// destination, a known guard-bypass to reach an internal host. IPv4-mapped IPv6 (::ffff:8.8.8.8) stays
// allowed: net.IPNet.Contains normalizes a mapped address to v4, so the v4 rows catch a mapped
// private/CGNAT address while a mapped public one matches nothing here.
var nonPublicCIDRs = func() []*net.IPNet {
	out := make([]*net.IPNet, 0, 12)
	for _, c := range []string{
		"0.0.0.0/8",       // "this host on this network" (RFC 1122) — IsUnspecified only catches the bare 0.0.0.0
		"100.64.0.0/10",   // CGNAT / shared address space (RFC 6598)
		"192.0.0.0/24",    // IETF protocol assignments (RFC 6890)
		"192.0.2.0/24",    // TEST-NET-1 (RFC 5737)
		"198.18.0.0/15",   // benchmarking (RFC 2544)
		"198.51.100.0/24", // TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",  // TEST-NET-3 (RFC 5737)
		"240.0.0.0/4",     // reserved / class E (RFC 1112)
		"64:ff9b::/96",    // NAT64 (RFC 6052) — embeds an IPv4 destination
		"100::/64",        // discard-only (RFC 6666)
		"2001:db8::/32",   // documentation (RFC 3849)
		"2002::/16",       // 6to4 (RFC 3056) — embeds an IPv4 destination
	} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// IsPublicIP reports whether an IP is a routable public address (the SSRF allowlist).
func IsPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	for _, n := range nonPublicCIDRs {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// GuardedDialContext is a DialContext for http.Transport that refuses to connect to a non-public host.
// It resolves the host, rejects if ANY resolved address is non-public, then dials the already-resolved
// public IP — so there is no rebind window, and each redirect hop (which re-dials through the same
// Transport) is screened too. timeout bounds both resolution and connect.
func GuardedDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		for _, ip := range ips {
			if !IsPublicIP(ip.IP) {
				return nil, fmt.Errorf("refusing to connect to non-public address for %s", host)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

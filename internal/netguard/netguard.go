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

// metadataIPs are the fixed cloud instance-metadata addresses. IPv4 IMDS + ECS task metadata are
// link-local (caught by IsLinkLocalUnicast), but the IPv6 IMDS address fd00:ec2::254 is a
// unique-local (fc00::/7) address that IsForbiddenIP would otherwise PERMIT (private is allowed for
// pentests) — so it is pinned explicitly. This is the credential-theft surface the Hugging Face
// incident escalated through (SSRF → 169.254.169.254 → instance-role creds).
var metadataIPs = func() []net.IP {
	out := []net.IP{}
	for _, s := range []string{"169.254.169.254", "169.254.170.2", "fd00:ec2::254"} {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}()

// IsForbiddenIP reports whether an IP is one an OFFENSIVE agent must NEVER reach — even when the
// target hostname is inside an authorized pentest scope. It is the SSRF-escalation surface: cloud
// metadata (link-local + the pinned IPv6 IMDS), loopback (back to the platform host), and the
// unspecified/multicast surface. It deliberately does NOT forbid RFC1918/private ranges: a pentest
// may legitimately target an in-scope internal host, so those are gated by scope, not by this guard.
// Use it as the dial-time guard for scope-bounded offensive tooling (webagent). Public/private both
// pass; only the never-legitimate targets are refused.
func IsForbiddenIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, m := range metadataIPs {
		if ip.Equal(m) {
			return true
		}
	}
	return false
}

// Resolver is the DNS seam (satisfied by *net.Resolver) so the dial guard is deterministically
// testable without real DNS — a test can resolve an "in-scope" name to a metadata IP and assert the
// guard refuses it.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ForbiddenDialContext is a DialContext for scope-bounded offensive tooling (the host-side webagent):
// it resolves the host, REJECTS if any resolved address is forbidden (so an in-scope name that
// rebinds to metadata is stopped), then dials the already-resolved IP so there is no rebind window and
// each redirect hop is re-screened. onDeny (nil-safe) fires with the offending host+IP on a rejection
// — the hook a circuit-breaker later trips on.
//
// It PERMITS private/RFC1918 (an authorized internal target — the scope allowlist gates which hosts
// may be dialed at all). allowLoopback permits 127.0.0.1/::1 too: the offensive agent runs host-side
// and legitimately targets local test servers, and loopback is already scope-gated. Cloud METADATA
// (the Hugging Face-incident credential-theft address) is refused REGARDLESS of allowLoopback — it is
// never a legitimate target.
func ForbiddenDialContext(timeout time.Duration, allowLoopback bool, onDeny func(host string, ip net.IP)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return forbiddenDialWith(net.DefaultResolver, timeout, allowLoopback, onDeny)
}

func forbiddenDialWith(res Resolver, timeout time.Duration, allowLoopback bool, onDeny func(host string, ip net.IP)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := res.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		for _, ip := range ips {
			if allowLoopback && ip.IP.IsLoopback() {
				continue // a scope-gated local target — metadata is still checked below
			}
			if IsForbiddenIP(ip.IP) {
				if onDeny != nil {
					onDeny(host, ip.IP)
				}
				return nil, fmt.Errorf("egress guard: refusing to connect to %s — %s is a forbidden address (cloud metadata / link-local)", host, ip.IP)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
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

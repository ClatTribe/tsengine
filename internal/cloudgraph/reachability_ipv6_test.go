package cloudgraph

import "testing"

// TestInternetReachable_IPv6: a security-group rule opening a port to ::/0 (the entire IPv6 internet —
// a real, common exposure on dual-stack / IPv6-enabled deployments) IS internet-reachable.
// InternetReachable only tested the IPv4 0.0.0.0/0 source, so a v6 internet rule read as "not
// reachable" → PruneUnreachable wrongly dropped a genuinely internet-exposed edge (a false negative,
// and a §10 violation: a ::/0 rule is NOT a definitive deny of internet reachability).
func TestInternetReachable_IPv6(t *testing.T) {
	v6open := []SGRule{{Proto: "tcp", CIDR: "::/0", PortFrom: 443, PortTo: 443}}
	if !InternetReachable(v6open, 443, "tcp") {
		t.Error("a rule opening 443 to ::/0 (IPv6 anywhere) must be internet-reachable")
	}
	// coverage, not overlap: a corporate IPv6 range must NOT read as internet-open.
	corp6 := []SGRule{{Proto: "tcp", CIDR: "2001:db8::/32", PortFrom: 443, PortTo: 443}}
	if InternetReachable(corp6, 443, "tcp") {
		t.Error("a corporate IPv6 /32 must NOT read as internet-open")
	}
	// a different v6 port is not reachable (the rule is port-scoped).
	if InternetReachable(v6open, 22, "tcp") {
		t.Error("::/0 on 443 must not make 22 reachable")
	}
}

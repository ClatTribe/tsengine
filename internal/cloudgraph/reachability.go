package cloudgraph

import (
	"encoding/json"
	"net"
	"strings"
)

// reachability.go adds REACHABILITY PRECISION — the "distinguish theoretical exposure from actually
// reachable risk" capability the agentic-cloud-security category treats as table stakes. The graph models
// network_reach as a boolean edge; that over-approximates "public" (a resource with a routable IP) into
// "internet-reachable" even when its security group only permits a corporate CIDR or a different port. A
// real cloud engineer asks: given the security-group ingress rules, can a packet from the internet
// actually hit the service port? This evaluator answers that, and PruneUnreachable (prune.go) uses it to
// drop the internet→resource edges the SG provably blocks — exactly like PruneUnauthorized does for IAM.
//
// Grounded (§10): the evaluator decides reachability from the resource's OWN ingress rules; an edge is
// pruned only on a DEFINITIVE "no rule permits this", and kept when rule data is absent/unparseable
// (absent data never prunes a genuinely-reachable path — recall preserved by construction).

// SGRule is one ingress (allow) rule of a security group / firewall: permit `Proto` traffic from `CIDR`
// to destination ports [PortFrom, PortTo]. Proto "" or "-1" or "all" means any protocol; PortFrom==0 &&
// PortTo==0 with an "all"-proto rule means all ports (the AWS "all traffic" rule shape).
type SGRule struct {
	Proto    string `json:"proto,omitempty"` // "tcp" | "udp" | "icmp" | "-1"/"all"/"" (any)
	CIDR     string `json:"cidr"`            // e.g. "0.0.0.0/0", "10.0.0.0/8", "203.0.113.4/32"
	PortFrom int    `json:"port_from,omitempty"`
	PortTo   int    `json:"port_to,omitempty"`
}

// ParseSGRules decodes the JSON array of ingress rules an ingest source places on a resource node
// (Node.Attrs["sg_ingress"]). Empty/blank → nil rules, no error (absent data is normal, not a failure).
func ParseSGRules(s string) ([]SGRule, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var rules []SGRule
	if err := json.Unmarshal([]byte(s), &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// protoMatches reports whether a rule's protocol covers the requested one. An empty / "-1" / "all" rule
// proto matches anything; otherwise an exact (case-insensitive) match.
func protoMatches(rule, want string) bool {
	r := strings.ToLower(strings.TrimSpace(rule))
	if r == "" || r == "-1" || r == "all" {
		return true
	}
	return r == strings.ToLower(strings.TrimSpace(want))
}

// portMatches reports whether `port` falls in the rule's range. A rule with PortFrom==0 && PortTo==0 is
// treated as "all ports" (the AWS all-traffic shape), matching any port.
func portMatches(r SGRule, port int) bool {
	if r.PortFrom == 0 && r.PortTo == 0 {
		return true
	}
	return port >= r.PortFrom && port <= r.PortTo
}

// ruleAllows reports whether the rule permits traffic from the WHOLE of srcCIDR to (port, proto). The
// CIDR test is COVERAGE (superset), not mere overlap: the rule applies only if its allowed range covers
// every address in srcCIDR. So a rule allowing a corp /24 does NOT permit srcCIDR=0.0.0.0/0 (the whole
// internet) — that's the precision the boolean edge lacked — but DOES permit a single host inside it.
func ruleAllows(r SGRule, srcCIDR string, port int, proto string) bool {
	if !protoMatches(r.Proto, proto) || !portMatches(r, port) {
		return false
	}
	return cidrCovers(r.CIDR, srcCIDR)
}

// Reachable reports whether traffic from srcCIDR can reach (port, proto) given the ingress rules.
func Reachable(rules []SGRule, srcCIDR string, port int, proto string) bool {
	for _, r := range rules {
		if ruleAllows(r, srcCIDR, port, proto) {
			return true
		}
	}
	return false
}

// InternetReachable reports whether the open internet can reach (port, proto) — i.e. the resource is
// ACTUALLY internet-exposed on that service port, not merely "has a public IP". Checks BOTH the IPv4
// (0.0.0.0/0) and IPv6 (::/0) "anywhere" sources: an SG rule opening the port to ::/0 is a real internet
// exposure on a dual-stack / IPv6 deployment, so ignoring it would let PruneUnreachable drop a genuinely
// reachable edge (a §10 recall violation — a ::/0 rule is not a definitive deny of internet reach).
func InternetReachable(rules []SGRule, port int, proto string) bool {
	return Reachable(rules, "0.0.0.0/0", port, proto) || Reachable(rules, "::/0", port, proto)
}

// cidrCovers reports whether the allowed range `rule` is a SUPERSET of (covers every address in) `src`.
// A bare IP is treated as a /32 (/128 for v6). On any parse failure it returns true — unparseable data
// must never silently prune a path (§10, recall preserved). True iff rule contains src's network address
// AND rule's prefix is the same or broader (fewer ones) than src's, so rule encloses all of src.
func cidrCovers(rule, src string) bool {
	nr, okr := parseCIDR(rule)
	ns, oks := parseCIDR(src)
	if !okr || !oks {
		return true // can't disprove coverage → conservatively keep
	}
	ro, _ := nr.Mask.Size()
	so, _ := ns.Mask.Size()
	return ro <= so && nr.Contains(ns.IP)
}

func parseCIDR(s string) (*net.IPNet, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n, true
	}
	// bare IP → host route
	if ip := net.ParseIP(s); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, true
	}
	return nil, false
}

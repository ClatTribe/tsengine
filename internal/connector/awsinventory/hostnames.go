package awsinventory

import (
	"sort"
	"strings"
)

// hostnames.go joins the hostnames a customer OWNS (their web, api and domain assets) to the cloud
// instance each one actually runs on.
//
// The graph already knew how to use the join — RawInstance.DNSNames becomes a web node wired to the
// resource, so the pentester's target (only ever a hostname) inherits that resource's outbound reach —
// and nothing ever filled it, so every web finding and every cloud path lived in separate graphs.
//
// THE ONE ADMISSIBLE EVIDENCE IS EXACT ADDRESS EQUALITY. A hostname is linked to an instance only when
// it RESOLVES to that instance's public IP. Not a similar name, not the same region, not "the only
// instance with port 443 open": estategraph refuses fuzzy identity because a wrong join fabricates an
// attack path, and a confident wrong path sends someone to harden the wrong box.
//
// What this CANNOT see, stated rather than hidden (Unlinked): a hostname served by another provider, or by
// a front door this inventory did not read, resolves to nothing in this account and stays unlinked.

// HostnameJoin reports what AttachHostnames did.
type HostnameJoin struct {
	Linked   map[string]string `json:"linked,omitempty"`   // hostname → resource id (instance, load balancer, distribution)
	Unlinked []string          `json:"unlinked,omitempty"` // resolved, but to nothing in this account
}

// AttachHostnames joins each resolved hostname to the resource it resolves to. resolved maps hostname →
// the addresses it resolved to; a hostname that did not resolve should be absent. Pure and deterministic.
func AttachHostnames(raw *RawAWS, resolved map[string][]string) HostnameJoin {
	hosts := make([]string, 0, len(resolved))
	for h := range resolved {
		hosts = append(hosts, h)
	}
	return AttachHostnamesTo(raw, hosts, resolved)
}

// AttachHostnamesTo joins the customer's hostnames to the resource that serves each one, on three kinds of
// evidence and no others:
//
//   - an INSTANCE when the hostname resolves to that instance's public address;
//   - a LOAD BALANCER when the hostname and the load balancer's own DNS name resolve to a common address.
//     ALB and NLB addresses are network interfaces in the customer's own VPC, dedicated to that load
//     balancer, so a shared address is the same machine — not a resemblance;
//   - a CLOUDFRONT DISTRIBUTION when the hostname is one of its ALIASES (exactly, or under a single-label
//     wildcard alias, which is CloudFront's own documented matching). Address equality is NOT admissible
//     here: CloudFront's edge addresses are shared by every customer, so two hostnames resolving to the
//     same edge says nothing about whose distribution serves either. An alias is a statement in this
//     account, accepted by AWS only against a certificate for the name.
//
// hosts is the customer's hostnames; resolved holds addresses for those hostnames AND for each load
// balancer's DNS name. A hostname that is an alias needs no resolution.
func AttachHostnamesTo(raw *RawAWS, hosts []string, resolved map[string][]string) HostnameJoin {
	out := HostnameJoin{Linked: map[string]string{}}
	byIP := map[string]int{}
	for i, in := range raw.Instances {
		if ip := strings.TrimSpace(in.PublicIPAddress); ip != "" {
			byIP[ip] = i
		}
	}
	lbByIP := map[string]int{}
	for i, lb := range raw.LoadBalancers {
		for _, ip := range lookup(resolved, lb.DNSName) {
			lbByIP[strings.TrimSpace(ip)] = i
		}
	}
	sorted := append([]string(nil), hosts...)
	sort.Strings(sorted)
	seen := map[string]bool{}
	for _, h := range sorted {
		host := normHost(h)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		ips := lookup(resolved, h)
		if i, ok := firstMatch(ips, byIP); ok {
			in := &raw.Instances[i]
			if !containsFold(in.DNSNames, host) {
				in.DNSNames = append(in.DNSNames, host)
			}
			out.Linked[host] = in.ID
			continue
		}
		if i, ok := firstMatch(ips, lbByIP); ok {
			lb := &raw.LoadBalancers[i]
			if !containsFold(lb.Hostnames, host) {
				lb.Hostnames = append(lb.Hostnames, host)
			}
			out.Linked[host] = lb.ARN
			continue
		}
		if i, ok := distributionFor(raw.Distributions, host); ok {
			d := &raw.Distributions[i]
			if !containsFold(d.Hostnames, host) {
				d.Hostnames = append(d.Hostnames, host)
			}
			out.Linked[host] = d.ARN
			continue
		}
		if len(ips) > 0 {
			out.Unlinked = append(out.Unlinked, host)
		}
	}
	return out
}

func lookup(resolved map[string][]string, h string) []string {
	if ips, ok := resolved[h]; ok {
		return ips
	}
	return resolved[normHost(h)]
}

func firstMatch(ips []string, idx map[string]int) (int, bool) {
	for _, ip := range ips {
		if i, ok := idx[strings.TrimSpace(ip)]; ok {
			return i, true
		}
	}
	return 0, false
}

// distributionFor returns the index of the distribution whose alias names host.
func distributionFor(ds []RawDistribution, host string) (int, bool) {
	for i, d := range ds {
		for _, a := range d.Aliases {
			if aliasMatches(normHost(a), host) {
				return i, true
			}
		}
	}
	return 0, false
}

// aliasMatches is CloudFront's alias rule: an exact name, or "*.example.com" matching exactly one label
// in place of the asterisk (www.example.com — not example.com, not a.b.example.com).
func aliasMatches(alias, host string) bool {
	if alias == host {
		return true
	}
	if !strings.HasPrefix(alias, "*.") {
		return false
	}
	suffix := alias[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := strings.TrimSuffix(host, suffix)
	return label != "" && !strings.Contains(label, ".")
}

func containsFold(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

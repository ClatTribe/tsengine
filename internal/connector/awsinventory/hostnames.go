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
// What this CANNOT see, stated rather than hidden (Unlinked): a hostname behind a load balancer, a CDN
// or another provider resolves to an address that is not an instance in this account, so it stays
// unlinked — which is the honest answer, since those front-ends are not in the inventory either.

// HostnameJoin reports what AttachHostnames did.
type HostnameJoin struct {
	Linked   map[string]string `json:"linked,omitempty"`   // hostname → instance id
	Unlinked []string          `json:"unlinked,omitempty"` // resolved, but to no instance in this account
}

// AttachHostnames adds each resolved hostname to the DNSNames of the instance whose public IP it
// resolves to. resolved maps hostname → the addresses it resolved to; a hostname that did not resolve
// should be absent. Pure and deterministic.
func AttachHostnames(raw *RawAWS, resolved map[string][]string) HostnameJoin {
	out := HostnameJoin{Linked: map[string]string{}}
	byIP := map[string]int{}
	for i, in := range raw.Instances {
		if ip := strings.TrimSpace(in.PublicIPAddress); ip != "" {
			byIP[ip] = i
		}
	}
	hosts := make([]string, 0, len(resolved))
	for h := range resolved {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if host == "" {
			continue
		}
		idx, hit := -1, false
		for _, ip := range resolved[h] {
			if i, ok := byIP[strings.TrimSpace(ip)]; ok {
				idx, hit = i, true
				break
			}
		}
		if !hit {
			out.Unlinked = append(out.Unlinked, host)
			continue
		}
		in := &raw.Instances[idx]
		if !containsFold(in.DNSNames, host) {
			in.DNSNames = append(in.DNSNames, host)
		}
		out.Linked[host] = in.ID
	}
	return out
}

func containsFold(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

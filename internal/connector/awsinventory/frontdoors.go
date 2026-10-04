package awsinventory

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// frontdoors.go maps load balancers and CloudFront distributions into the graph. See RawLoadBalancer and
// RawDistribution for what each edge rests on; the rule throughout is that an edge exists only where AWS
// itself states the relationship (a registration, an origin domain, a listener open to the internet).

func buildFrontDoors(inv *cloudgraph.Inventory, raw RawAWS, sgByID map[string]RawSecurityGroup) {
	known := map[string]bool{}
	for _, r := range inv.Resources {
		known[r.ID] = true
	}
	lbByDNS := map[string]string{}
	for _, lb := range raw.LoadBalancers {
		if strings.TrimSpace(lb.ARN) == "" {
			continue
		}
		internet := strings.EqualFold(lb.Scheme, "internet-facing")
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: lb.ARN, Kind: cloudgraph.KindResource, Type: "load_balancer", Name: lb.Name, Region: lb.Region,
			Public: internet, DNSNames: lb.Hostnames, Tags: map[string]string{"lb_type": lb.Type},
		})
		known[lb.ARN] = true
		if d := normHost(lb.DNSName); d != "" {
			lbByDNS[d] = lb.ARN
		}
		if internet && lbInternetReachable(lb, sgByID) {
			inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: lb.ARN})
		}
		for _, t := range append(append([]string{}, lb.TargetInstances...), lb.TargetFunctions...) {
			// Only to a target this inventory actually holds: an edge to an id with no node reads
			// downstream as a real relationship to nothing.
			if t = strings.TrimSpace(t); t != "" && known[t] {
				inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: lb.ARN, To: t})
			}
		}
	}

	bucketByOrigin := map[string]string{}
	for _, b := range raw.Buckets {
		id := b.ARN
		if id == "" {
			id = "arn:aws:s3:::" + b.Name
		}
		for _, d := range bucketOriginDomains(b.Name, b.Region) {
			bucketByOrigin[d] = id
		}
	}

	for _, d := range raw.Distributions {
		if strings.TrimSpace(d.ARN) == "" {
			continue
		}
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: d.ARN, Kind: cloudgraph.KindResource, Type: "cloudfront_distribution", Name: d.ID,
			Public: d.Enabled && !d.ViewerRestricted, DNSNames: distributionNames(d),
		})
		if d.Enabled && !d.ViewerRestricted {
			inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: d.ARN})
		}
		for _, o := range d.Origins {
			o = normHost(o)
			if lb, ok := lbByDNS[o]; ok {
				inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: d.ARN, To: lb})
			} else if b, ok := bucketByOrigin[o]; ok {
				inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: d.ARN, To: b})
			}
		}
	}
}

// lbInternetReachable: a load balancer with security groups is reachable only when one of them opens a
// listener port to the internet (the CIDR-coverage test instances get). One that was read and has NO
// security groups — an NLB — passes traffic on its listeners, so any listener is the edge. One whose
// groups were not read asserts nothing.
func lbInternetReachable(lb RawLoadBalancer, sgByID map[string]RawSecurityGroup) bool {
	if len(lb.Listeners) == 0 {
		return false
	}
	if len(lb.SGIDs) == 0 {
		return lb.SGsKnown
	}
	var rules []cloudgraph.SGRule
	for _, id := range lb.SGIDs {
		rs, err := cloudgraph.ParseSGRules(sgByID[id].IngressJSON)
		if err != nil {
			continue
		}
		rules = append(rules, rs...)
	}
	for _, l := range lb.Listeners {
		proto := "tcp"
		if strings.EqualFold(l.Protocol, "udp") {
			proto = "udp"
		}
		if l.Port > 0 && cloudgraph.InternetReachable(rules, l.Port, proto) {
			return true
		}
	}
	return false
}

// bucketOriginDomains are the domain names AWS gives a bucket as a CloudFront origin: the global and
// regional REST endpoints, in both the dot and the legacy dash form. Exact forms only — a website-hosting
// endpoint or a custom domain is not matched, because matching on a name that merely contains the bucket
// is how a distribution gets wired to someone else's bucket.
func bucketOriginDomains(name, region string) []string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return nil
	}
	out := []string{name + ".s3.amazonaws.com"}
	if r := strings.ToLower(strings.TrimSpace(region)); r != "" {
		out = append(out, name+".s3."+r+".amazonaws.com", name+".s3-"+r+".amazonaws.com")
	}
	return out
}

func normHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

// distributionNames are the concrete hostnames a distribution answers for: its exact aliases plus the
// customer hostnames matched under a wildcard. A wildcard is a pattern, not a name, and a node named
// "*.example.com" would read as a host nobody can visit.
func distributionNames(d RawDistribution) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range append(append([]string{}, d.Aliases...), d.Hostnames...) {
		a = normHost(a)
		if a == "" || strings.HasPrefix(a, "*.") || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

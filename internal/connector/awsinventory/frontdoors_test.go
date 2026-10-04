package awsinventory

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

const (
	lbARN   = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc"
	lbDNS   = "web-123.us-east-1.elb.amazonaws.com"
	distARN = "arn:aws:cloudfront::111122223333:distribution/E1"
	open443 = `[{"proto":"tcp","cidr":"0.0.0.0/0","port_from":443,"port_to":443}]`
	corp443 = `[{"proto":"tcp","cidr":"10.0.0.0/8","port_from":443,"port_to":443}]`
)

func reaches(inv cloudgraph.Inventory, from, to string) bool {
	for _, r := range inv.Reaches {
		if r.From == from && r.To == to {
			return true
		}
	}
	return false
}

// The architecture most web apps actually run: an internet-facing ALB in front of instances with no public
// address. Before load balancers were read, the instance had no internet edge at all, so no path to it —
// or through its role to the data it can read — could ever be drawn.
func TestBuild_InternetFacingALBReachesItsRegisteredTargets(t *testing.T) {
	inv := Build(RawAWS{
		SGs:       []RawSecurityGroup{{ID: "sg-lb", IngressJSON: open443}},
		Instances: []RawInstance{{ID: "i-app"}}, // private: no public IP
		LoadBalancers: []RawLoadBalancer{{
			ARN: lbARN, DNSName: lbDNS, Type: "application", Scheme: "internet-facing",
			SGIDs: []string{"sg-lb"}, SGsKnown: true, Listeners: []RawListener{{Port: 443, Protocol: "HTTPS"}},
			TargetInstances: []string{"i-app", "i-not-in-inventory"},
		}},
	})
	if !reaches(inv, cloudgraph.InternetID, lbARN) {
		t.Error("an internet-facing ALB whose SG opens its listener port must be reachable from the internet")
	}
	if !reaches(inv, lbARN, "i-app") {
		t.Error("the ALB must reach the instance REGISTERED behind it")
	}
	if reaches(inv, lbARN, "i-not-in-inventory") {
		t.Error("an edge to a target the inventory does not hold reads as a relationship to nothing")
	}
}

// The refusals: each is a case where drawing the internet edge would invent exposure.
func TestBuild_LoadBalancerInternetEdgeRefusals(t *testing.T) {
	sgs := []RawSecurityGroup{{ID: "sg-corp", IngressJSON: corp443}, {ID: "sg-open", IngressJSON: open443}}
	for name, lb := range map[string]RawLoadBalancer{
		"internal scheme":             {Scheme: "internal", SGIDs: []string{"sg-open"}, SGsKnown: true, Listeners: []RawListener{{Port: 443}}},
		"SG open only to a corp CIDR": {Scheme: "internet-facing", SGIDs: []string{"sg-corp"}, SGsKnown: true, Listeners: []RawListener{{Port: 443}}},
		"SG open on a different port": {Scheme: "internet-facing", SGIDs: []string{"sg-open"}, SGsKnown: true, Listeners: []RawListener{{Port: 8443}}},
		"no listeners":                {Scheme: "internet-facing", SGIDs: []string{"sg-open"}, SGsKnown: true},
		"security groups never read":  {Scheme: "internet-facing", Listeners: []RawListener{{Port: 443}}},
	} {
		lb.ARN = lbARN
		if inv := Build(RawAWS{SGs: sgs, LoadBalancers: []RawLoadBalancer{lb}}); reaches(inv, cloudgraph.InternetID, lbARN) {
			t.Errorf("%s: internet edge asserted", name)
		}
	}
	// An NLB that was read and genuinely has no security groups passes traffic on its listeners.
	nlb := RawLoadBalancer{ARN: lbARN, Type: "network", Scheme: "internet-facing", SGsKnown: true, Listeners: []RawListener{{Port: 22}}}
	if inv := Build(RawAWS{LoadBalancers: []RawLoadBalancer{nlb}}); !reaches(inv, cloudgraph.InternetID, lbARN) {
		t.Error("an internet-facing NLB with no security groups is reachable on its listeners")
	}
}

// The case this file was written for: a bucket that is NOT public, holding customer data, served through
// CloudFront. Every bucket-level check reads it as private; the path to it from the internet is real.
func TestBuild_PrivateSensitiveBucketServedThroughCloudFront(t *testing.T) {
	bucket := "arn:aws:s3:::cust-exports"
	inv := Build(RawAWS{
		Buckets: []RawBucket{{Name: "cust-exports", Region: "eu-west-1", Sensitive: true}},
		Distributions: []RawDistribution{{
			ARN: distARN, ID: "E1", Enabled: true, Aliases: []string{"files.acme.com"},
			Origins: []string{"cust-exports.s3.eu-west-1.amazonaws.com"},
		}},
	})
	if !reaches(inv, cloudgraph.InternetID, distARN) || !reaches(inv, distARN, bucket) {
		t.Fatalf("internet → distribution → private bucket was not drawn: %+v", inv.Reaches)
	}
	if reaches(inv, cloudgraph.InternetID, bucket) {
		t.Error("the bucket itself is not public and must not gain a direct internet edge")
	}
	s := cloudgraph.Ingest(inv)
	if n := s.Node(bucket); n == nil || n.Kind != cloudgraph.KindData {
		t.Error("the bucket should remain a declared crown jewel")
	}
}

func TestBuild_CloudFrontRefusals(t *testing.T) {
	base := RawAWS{
		Buckets:       []RawBucket{{Name: "b", Region: "us-east-1"}},
		LoadBalancers: []RawLoadBalancer{{ARN: lbARN, DNSName: lbDNS, Scheme: "internal"}},
	}
	// Signed URLs on every behaviour: only the key holder gets through.
	restricted := base
	restricted.Distributions = []RawDistribution{{ARN: distARN, Enabled: true, ViewerRestricted: true, Origins: []string{"b.s3.amazonaws.com"}}}
	if reaches(Build(restricted), cloudgraph.InternetID, distARN) {
		t.Error("a viewer-restricted distribution has no anonymous internet edge")
	}
	disabled := base
	disabled.Distributions = []RawDistribution{{ARN: distARN, Origins: []string{"b.s3.amazonaws.com"}}}
	if reaches(Build(disabled), cloudgraph.InternetID, distARN) {
		t.Error("a disabled distribution serves nothing")
	}
	// Origins are joined on the EXACT domain AWS gives the bucket/LB, never on a name that contains it.
	near := base
	near.Distributions = []RawDistribution{{ARN: distARN, Enabled: true, Origins: []string{
		"b.s3-website-us-east-1.amazonaws.com", "b.example.com", "other-" + lbDNS,
	}}}
	inv := Build(near)
	if reaches(inv, distARN, "arn:aws:s3:::b") || reaches(inv, distARN, lbARN) {
		t.Errorf("an origin was joined on a resemblance: %+v", inv.Reaches)
	}
	// And the exact forms do join, including a load balancer origin with a trailing dot and mixed case.
	exact := base
	exact.Distributions = []RawDistribution{{ARN: distARN, Enabled: true, Origins: []string{"B.S3.AMAZONAWS.COM", lbDNS + "."}}}
	inv = Build(exact)
	if !reaches(inv, distARN, "arn:aws:s3:::b") || !reaches(inv, distARN, lbARN) {
		t.Errorf("exact origin domains did not join: %+v", inv.Reaches)
	}
}

func TestAttachHostnamesTo_LoadBalancerAndCloudFront(t *testing.T) {
	raw := RawAWS{
		Instances:     []RawInstance{{ID: "i-1", PublicIPAddress: "203.0.113.5"}},
		LoadBalancers: []RawLoadBalancer{{ARN: lbARN, DNSName: lbDNS}},
		Distributions: []RawDistribution{{ARN: distARN, Aliases: []string{"*.cdn.acme.com", "www.acme.com"}}},
	}
	resolved := map[string][]string{
		"box.acme.com":       {"203.0.113.5"},
		"app.acme.com":       {"198.51.100.7", "198.51.100.8"},
		lbDNS:                {"198.51.100.8", "198.51.100.9"},
		"www.acme.com":       {"13.32.0.1"}, // a CloudFront edge address — shared, never evidence
		"img.cdn.acme.com":   {"13.32.0.1"},
		"elsewhere.acme.com": {"192.0.2.1"},
	}
	hosts := []string{"box.acme.com", "app.acme.com", "www.acme.com", "img.cdn.acme.com", "a.b.cdn.acme.com",
		"cdn.acme.com", "elsewhere.acme.com", "store.acme.com"}
	j := AttachHostnamesTo(&raw, hosts, resolved)

	want := map[string]string{"box.acme.com": "i-1", "app.acme.com": lbARN, "www.acme.com": distARN, "img.cdn.acme.com": distARN}
	for h, id := range want {
		if j.Linked[h] != id {
			t.Errorf("%s linked to %q, want %q", h, j.Linked[h], id)
		}
	}
	for _, h := range []string{"a.b.cdn.acme.com", "cdn.acme.com", "elsewhere.acme.com", "store.acme.com"} {
		if _, ok := j.Linked[h]; ok {
			t.Errorf("%s must not be linked (wildcard is one label; no evidence otherwise)", h)
		}
	}
	if len(j.Unlinked) != 1 || j.Unlinked[0] != "elsewhere.acme.com" {
		t.Errorf("only a host that RESOLVED and matched nothing is unlinked, got %v", j.Unlinked)
	}
	if len(raw.LoadBalancers[0].Hostnames) != 1 || raw.LoadBalancers[0].Hostnames[0] != "app.acme.com" {
		t.Errorf("load balancer hostnames: %v", raw.LoadBalancers[0].Hostnames)
	}
	// The wildcard itself never becomes a hostname node; the concrete matches do.
	inv := Build(raw)
	for _, r := range inv.Resources {
		if r.ID == distARN {
			got := map[string]bool{}
			for _, n := range r.DNSNames {
				got[n] = true
			}
			if got["*.cdn.acme.com"] || !got["www.acme.com"] || !got["img.cdn.acme.com"] {
				t.Errorf("distribution names: %v", r.DNSNames)
			}
		}
	}
}

// CloudFront edge addresses are shared by every customer: a hostname resolving to the same edge as an
// alias of OURS is not ours unless it is itself an alias.
func TestAttachHostnamesTo_SharedCDNAddressIsNotEvidence(t *testing.T) {
	raw := RawAWS{Distributions: []RawDistribution{{ARN: distARN, Aliases: []string{"www.acme.com"}}}}
	j := AttachHostnamesTo(&raw, []string{"someone-else.example"}, map[string][]string{
		"www.acme.com": {"13.32.0.1"}, "someone-else.example": {"13.32.0.1"},
	})
	if _, ok := j.Linked["someone-else.example"]; ok {
		t.Error("a shared CDN edge address was taken as evidence of ownership")
	}
}

package cloudgraph

import "testing"

func TestInternetReachable(t *testing.T) {
	open := []SGRule{{Proto: "tcp", CIDR: "0.0.0.0/0", PortFrom: 22, PortTo: 22}}
	corp := []SGRule{{Proto: "tcp", CIDR: "203.0.113.0/24", PortFrom: 22, PortTo: 22}}
	web := []SGRule{{Proto: "tcp", CIDR: "0.0.0.0/0", PortFrom: 443, PortTo: 443}}
	all := []SGRule{{Proto: "-1", CIDR: "0.0.0.0/0"}} // all traffic, all ports

	if !InternetReachable(open, 22, "tcp") {
		t.Error("0.0.0.0/0 on port 22 must be internet-reachable")
	}
	if InternetReachable(corp, 22, "tcp") {
		t.Error("a corp-CIDR-only rule must NOT be internet-reachable (the precision win)")
	}
	if InternetReachable(web, 22, "tcp") {
		t.Error("a 443-only rule must not make port 22 internet-reachable")
	}
	if !InternetReachable(all, 22, "tcp") || !InternetReachable(all, 3306, "tcp") {
		t.Error("an all-traffic 0.0.0.0/0 rule must reach any port")
	}
	// proto mismatch
	udp := []SGRule{{Proto: "udp", CIDR: "0.0.0.0/0", PortFrom: 53, PortTo: 53}}
	if InternetReachable(udp, 53, "tcp") {
		t.Error("a udp rule must not match a tcp request")
	}
	// a corp range that OVERLAPS the requested source is reachable from THAT source (general form)
	if !Reachable(corp, "203.0.113.5/32", 22, "tcp") {
		t.Error("a host inside the allowed corp CIDR must be able to reach the port")
	}
}

func TestParseSGRules_AbsentIsNotError(t *testing.T) {
	if r, err := ParseSGRules(""); err != nil || r != nil {
		t.Errorf("blank rules must parse to (nil,nil), got %v %v", r, err)
	}
	if _, err := ParseSGRules("not json"); err == nil {
		t.Error("malformed JSON should error (so the prune keeps the edge)")
	}
}

// End-to-end: a public resource SG-restricted to a corp CIDR has its internet reach edge PRUNED, so the
// internet→resource path disappears; an identically-public resource open to 0.0.0.0/0 keeps its path.
func TestPruneUnreachable_EndToEnd(t *testing.T) {
	mk := func(id, ingress string) *Node {
		return &Node{ID: id, Kind: KindResource, Type: "AWS::EC2::Instance", Public: true,
			Attrs: map[string]string{"service_port": "22", "service_proto": "tcp", "sg_ingress": ingress}}
	}
	s := New("acct", "aws")
	s.AddNode(&Node{ID: InternetID, Kind: KindNetwork})
	s.AddNode(mk("ec2-restricted", `[{"proto":"tcp","cidr":"203.0.113.0/24","port_from":22,"port_to":22}]`))
	s.AddNode(mk("ec2-open", `[{"proto":"tcp","cidr":"0.0.0.0/0","port_from":22,"port_to":22}]`))
	s.AddNode(&Node{ID: "ec2-nodata", Kind: KindResource, Public: true}) // no SG data → must be kept
	s.AddEdge(Edge{From: InternetID, To: "ec2-restricted", Kind: EdgeNetworkReach})
	s.AddEdge(Edge{From: InternetID, To: "ec2-open", Kind: EdgeNetworkReach})
	s.AddEdge(Edge{From: InternetID, To: "ec2-nodata", Kind: EdgeNetworkReach})

	s.PruneUnreachable()

	has := func(to string) bool {
		for _, e := range s.Edges {
			if e.Kind == EdgeNetworkReach && e.From == InternetID && e.To == to {
				return true
			}
		}
		return false
	}
	if has("ec2-restricted") {
		t.Error("the corp-CIDR-restricted resource's internet edge must be PRUNED (theoretical, not reachable)")
	}
	if !has("ec2-open") {
		t.Error("the 0.0.0.0/0-open resource's internet edge must be KEPT (really reachable)")
	}
	if !has("ec2-nodata") {
		t.Error("a resource with no SG data must be KEPT (absent data never prunes — §10)")
	}
}

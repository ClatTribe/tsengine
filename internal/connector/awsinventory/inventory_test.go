package awsinventory

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// A role's trust policy that names a concrete principal → exactly one trust edge to that principal.
func TestBuild_TrustEdgeFromPolicy(t *testing.T) {
	raw := RawAWS{
		AccountID: "111122223333",
		Users:     []RawIAMUser{{ARN: "arn:aws:iam::111122223333:user/dev", Name: "dev"}},
		Roles: []RawIAMRole{{
			ARN: "arn:aws:iam::111122223333:role/admin", Name: "admin", Admin: true,
			TrustPolicyJSON: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/dev"},"Action":"sts:AssumeRole"}]}`,
		}},
	}
	inv := Build(raw)
	if len(inv.Trusts) != 1 {
		t.Fatalf("want 1 trust edge, got %d: %+v", len(inv.Trusts), inv.Trusts)
	}
	tr := inv.Trusts[0]
	if tr.Principal != "arn:aws:iam::111122223333:user/dev" || tr.Role != "arn:aws:iam::111122223333:role/admin" {
		t.Fatalf("wrong trust edge: %+v", tr)
	}
	// the role must be flagged privileged (it's admin) — the crown-jewel signal
	var foundAdmin bool
	for _, r := range inv.Resources {
		if r.ID == raw.Roles[0].ARN && r.Privileged {
			foundAdmin = true
		}
	}
	if !foundAdmin {
		t.Error("admin role should be Privileged")
	}
	// and the whole inventory must ingest into a real graph (the end-to-end seam)
	if snap := cloudgraph.Ingest(inv); snap.Node(raw.Roles[0].ARN) == nil {
		t.Error("ingested snapshot is missing the role node")
	}
}

// REACHABILITY PRECISION: an internet→resource edge is emitted ONLY when the resource is public AND its SG
// actually opens the service port to 0.0.0.0/0. A corp-CIDR-only rule is NOT internet-open (grounded).
func TestBuild_InternetReachOnlyWhenSGActuallyOpen(t *testing.T) {
	base := RawAWS{
		AccountID: "111122223333",
		SGs: []RawSecurityGroup{
			{ID: "sg-open", IngressJSON: `[{"proto":"tcp","cidr":"0.0.0.0/0","port_from":22,"port_to":22}]`},
			{ID: "sg-corp", IngressJSON: `[{"proto":"tcp","cidr":"10.0.0.0/8","port_from":22,"port_to":22}]`},
		},
	}

	// public IP + SG opens 22 to the world → one internet reach edge
	open := base
	open.Instances = []RawInstance{{ID: "i-open", PublicIP: true, SGIDs: []string{"sg-open"}, ServicePort: 22}}
	if got := internetReaches(Build(open)); got != 1 {
		t.Fatalf("public+open SG should yield 1 internet reach, got %d", got)
	}

	// public IP but SG only permits a corp CIDR → NO internet reach (theoretical exposure, not real)
	corp := base
	corp.Instances = []RawInstance{{ID: "i-corp", PublicIP: true, SGIDs: []string{"sg-corp"}, ServicePort: 22}}
	if got := internetReaches(Build(corp)); got != 0 {
		t.Fatalf("corp-CIDR-only SG must NOT yield an internet reach, got %d", got)
	}

	// no public IP → never reachable regardless of SG
	priv := base
	priv.Instances = []RawInstance{{ID: "i-priv", PublicIP: false, SGIDs: []string{"sg-open"}, ServicePort: 22}}
	if got := internetReaches(Build(priv)); got != 0 {
		t.Fatalf("private instance must NOT yield an internet reach, got %d", got)
	}
}

// A public bucket reaches the internet; a sensitive bucket is KindData/SensHigh (the crown-jewel signal).
func TestBuild_Buckets(t *testing.T) {
	inv := Build(RawAWS{
		AccountID: "111122223333",
		Buckets: []RawBucket{
			{Name: "public-logs", Public: true},
			{Name: "prod-pii", Sensitive: true},
		},
	})
	if got := internetReaches(inv); got != 1 {
		t.Fatalf("one public bucket should yield 1 internet reach, got %d", got)
	}
	var sawData bool
	for _, r := range inv.Resources {
		if r.Name == "prod-pii" {
			if r.Kind != cloudgraph.KindData || r.Sensitive != cloudgraph.SensHigh {
				t.Errorf("sensitive bucket should be KindData/SensHigh, got %s/%s", r.Kind, r.Sensitive)
			}
			sawData = true
		}
	}
	if !sawData {
		t.Error("sensitive bucket missing from resources")
	}
}

// A clean account (no public resources, no cross-principal trust) yields a graph with ZERO internet edges.
func TestBuild_CleanAccountHasNoInternetEdges(t *testing.T) {
	inv := Build(RawAWS{
		AccountID: "111122223333",
		Users:     []RawIAMUser{{ARN: "arn:aws:iam::111122223333:user/dev", Name: "dev"}},
		Instances: []RawInstance{{ID: "i-1", PublicIP: false, ServicePort: 22}},
		Buckets:   []RawBucket{{Name: "private", Public: false}},
	})
	if got := internetReaches(inv); got != 0 {
		t.Fatalf("clean account must have 0 internet edges, got %d", got)
	}
	if len(inv.Resources) != 3 {
		t.Fatalf("want 3 resources, got %d", len(inv.Resources))
	}
}

// Collect runs the fetcher then maps; a nil fetcher errors rather than panicking.
func TestCollect_FetcherSeam(t *testing.T) {
	if _, err := Collect(context.Background(), nil); err == nil {
		t.Fatal("nil fetcher should error")
	}
	fake := fetcherFunc(func(context.Context) (RawAWS, error) {
		return RawAWS{AccountID: "111122223333", Buckets: []RawBucket{{Name: "x", Public: true}}}, nil
	})
	inv, err := Collect(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}
	if internetReaches(inv) != 1 {
		t.Error("collect should map the fetched public bucket into an internet edge")
	}
}

// trustPrincipals tolerates AWS's string-or-array shapes and skips a bare "*"/Service principal.
func TestTrustPrincipals_Shapes(t *testing.T) {
	arr := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:a","arn:b"]}}]}`
	if got := trustPrincipals(arr); len(got) != 2 {
		t.Errorf("array Principal.AWS: want 2, got %v", got)
	}
	wildcard := `{"Statement":{"Effect":"Allow","Principal":"*"}}`
	if got := trustPrincipals(wildcard); len(got) != 0 {
		t.Errorf("bare wildcard principal should yield no concrete edge, got %v", got)
	}
	svc := `{"Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}}`
	if got := trustPrincipals(svc); len(got) != 0 {
		t.Errorf("service principal should yield no AWS-principal edge, got %v", got)
	}
	if got := trustPrincipals(""); got != nil {
		t.Errorf("empty doc should yield nil, got %v", got)
	}
}

func internetReaches(inv cloudgraph.Inventory) int {
	n := 0
	for _, r := range inv.Reaches {
		if r.From == cloudgraph.InternetID {
			n++
		}
	}
	return n
}

type fetcherFunc func(context.Context) (RawAWS, error)

func (f fetcherFunc) Fetch(ctx context.Context) (RawAWS, error) { return f(ctx) }

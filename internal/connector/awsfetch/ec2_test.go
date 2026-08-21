package awsfetch

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
)

type fakeCompute struct {
	ins []Instance
	sgs []SecurityGroup
	err error
}

func (f fakeCompute) ListCompute(context.Context) ([]Instance, []SecurityGroup, error) {
	return f.ins, f.sgs, f.err
}

// THE WHOLE POINT OF ALL THREE SURFACES: a live fetch must produce an inventory cloudgraph can
// actually build a path from. Buckets alone form no chain; principals give the actors; security
// groups decide whether "exposed" is real.
func TestFetch_AllThreeSurfacesProduceAUsableGraph(t *testing.T) {
	res, err := Fetcher{
		AccountID: "123456789012",
		Buckets:   fakeLister{out: []Bucket{{Name: "customer-data", Public: true}}},
		Principals: fakeIAM{out: []Principal{
			{ARN: "arn:aws:iam::123456789012:role/app", Name: "app", Role: true,
				Trust: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`,
				// A COMPLETE read includes the policy documents. Without them the fetcher
				// correctly reports iam-policies as unread, because no escalation path can
				// be computed — and this test claims every surface was read.
				Policies: []string{`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`}},
		}},
		Compute: fakeCompute{
			ins: []Instance{{ID: "i-1", PublicIP: true, SGIDs: []string{"sg-1"}}},
			sgs: []SecurityGroup{{ID: "sg-1", Rules: []cloudgraph.SGRule{
				{Proto: "tcp", CIDR: "0.0.0.0/0", PortFrom: 443, PortTo: 443},
			}}},
		},
	}.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Every surface read, nothing left unread.
	for _, s := range []string{"s3", "iam", "ec2"} {
		if !res.Covers(s) {
			t.Errorf("%q was read but not reported as covered", s)
		}
	}
	if len(res.Skipped) != 0 {
		t.Errorf("surfaces reported as skipped when all three were read: %v", res.Skipped)
	}

	// And the inventory must actually build into a graph with the pieces a path needs.
	inv := awsinventory.Build(res.Raw)
	if len(inv.Resources) < 3 {
		t.Fatalf("inventory has %d resources; a bucket, a role and an instance were fetched", len(inv.Resources))
	}
	if len(inv.Trusts) == 0 {
		t.Error("no trust edges — the role's trust policy did not become a graph edge, so no lateral " +
			"movement can ever be shown")
	}
}

// The ingress rules are what cloudgraph.InternetReachable evaluates. If they do not survive into the
// inventory in its own shape, every instance looks uniformly safe.
func TestIngressRules_SurviveIntoTheInventoryInCloudgraphShape(t *testing.T) {
	res, err := Fetcher{
		AccountID: "1234",
		Buckets:   fakeLister{out: []Bucket{{Name: "b"}}},
		Compute: fakeCompute{
			ins: []Instance{{ID: "i-1", PublicIP: true, SGIDs: []string{"sg-1"}}},
			sgs: []SecurityGroup{{ID: "sg-1", Rules: []cloudgraph.SGRule{
				{Proto: "tcp", CIDR: "0.0.0.0/0", PortFrom: 22, PortTo: 22},
			}}},
		},
	}.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Raw.SGs) != 1 {
		t.Fatalf("got %d security groups, want 1", len(res.Raw.SGs))
	}
	// It must parse back through the SAME function cloudgraph uses.
	rules, perr := cloudgraph.ParseSGRules(res.Raw.SGs[0].IngressJSON)
	if perr != nil {
		t.Fatalf("the emitted ingress JSON does not parse with cloudgraph.ParseSGRules: %v", perr)
	}
	if len(rules) != 1 || rules[0].CIDR != "0.0.0.0/0" || rules[0].PortFrom != 22 {
		t.Errorf("the rule was mangled in transit: %+v", rules)
	}
}

// A group with NO ingress must read as "no openings", not as absent data. ParseSGRules treats blank
// as absent, and absent means unevaluated — which cloudgraph correctly refuses to call safe.
func TestMarshalRules_EmptyIsAnEmptyArrayNotNull(t *testing.T) {
	got := marshalRules(nil)
	if got == "null" || strings.TrimSpace(got) == "" {
		t.Fatalf("empty rules marshalled to %q — that reads as unknown, not as 'no openings'", got)
	}
	var rules []cloudgraph.SGRule
	if err := json.Unmarshal([]byte(got), &rules); err != nil {
		t.Fatalf("empty rules did not marshal to valid JSON: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("empty rules produced %d entries", len(rules))
	}
}

// Terminated hosts are not attack surface. Counting them inflates the graph with resources nobody
// can reach, which buries the ones that matter.
func TestListCompute_SkipsTerminatedInstances(t *testing.T) {
	// Exercised through the mapper: a fetcher whose reader already filtered them yields only live ones.
	res, _ := Fetcher{
		AccountID: "1234",
		Buckets:   fakeLister{out: []Bucket{{Name: "b"}}},
		Compute:   fakeCompute{ins: []Instance{{ID: "i-live", PublicIP: true}}},
	}.Fetch(context.Background())
	if len(res.Raw.Instances) != 1 || res.Raw.Instances[0].ID != "i-live" {
		t.Errorf("expected only the live instance, got %+v", res.Raw.Instances)
	}
}

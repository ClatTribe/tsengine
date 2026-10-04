package awsfetch

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
)

type fakeLBs struct {
	out []LoadBalancer
	err error
}

func (f fakeLBs) ListLoadBalancers(context.Context) ([]LoadBalancer, error) { return f.out, f.err }

type fakeDists struct {
	out []Distribution
	err error
}

func (f fakeDists) ListDistributions(context.Context) ([]Distribution, error) { return f.out, f.err }

// ── the SDK-shaped listers ─────────────────────────────────────────────────────────────────────────

type fakeELBAPI struct {
	listenersErr error
}

func (fakeELBAPI) DescribeLoadBalancers(_ context.Context, _ *elb.DescribeLoadBalancersInput, _ ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error) {
	return &elb.DescribeLoadBalancersOutput{LoadBalancers: []elbtypes.LoadBalancer{
		{LoadBalancerArn: aws.String("arn:lb/web"), LoadBalancerName: aws.String("web"), DNSName: aws.String("web.elb.amazonaws.com"),
			Type: elbtypes.LoadBalancerTypeEnumApplication, Scheme: elbtypes.LoadBalancerSchemeEnumInternetFacing,
			SecurityGroups: []string{"sg-lb"}},
	}}, nil
}

func (f fakeELBAPI) DescribeListeners(context.Context, *elb.DescribeListenersInput, ...func(*elb.Options)) (*elb.DescribeListenersOutput, error) {
	if f.listenersErr != nil {
		return nil, f.listenersErr
	}
	return &elb.DescribeListenersOutput{Listeners: []elbtypes.Listener{{Port: aws.Int32(443), Protocol: elbtypes.ProtocolEnumHttps}}}, nil
}

func (fakeELBAPI) DescribeTargetGroups(context.Context, *elb.DescribeTargetGroupsInput, ...func(*elb.Options)) (*elb.DescribeTargetGroupsOutput, error) {
	return &elb.DescribeTargetGroupsOutput{TargetGroups: []elbtypes.TargetGroup{
		{TargetGroupArn: aws.String("tg-i"), TargetType: elbtypes.TargetTypeEnumInstance},
		{TargetGroupArn: aws.String("tg-fn"), TargetType: elbtypes.TargetTypeEnumLambda},
		{TargetGroupArn: aws.String("tg-ip"), TargetType: elbtypes.TargetTypeEnumIp},
	}}, nil
}

func (fakeELBAPI) DescribeTargetHealth(_ context.Context, in *elb.DescribeTargetHealthInput, _ ...func(*elb.Options)) (*elb.DescribeTargetHealthOutput, error) {
	id := map[string]string{"tg-i": "i-app", "tg-fn": "arn:aws:lambda:us-east-1:1:function:f", "tg-ip": "10.0.0.9"}[aws.ToString(in.TargetGroupArn)]
	return &elb.DescribeTargetHealthOutput{TargetHealthDescriptions: []elbtypes.TargetHealthDescription{
		{Target: &elbtypes.TargetDescription{Id: aws.String(id)}},
	}}, nil
}

func TestELBLister_ReadsListenersAndRegisteredTargetsByType(t *testing.T) {
	lbs, err := (&ELBLister{Region: "us-east-1", api: fakeELBAPI{}}).ListLoadBalancers(context.Background())
	if err != nil || len(lbs) != 1 {
		t.Fatalf("lbs=%v err=%v", lbs, err)
	}
	lb := lbs[0]
	if lb.Scheme != "internet-facing" || len(lb.Listeners) != 1 || lb.Listeners[0].Port != 443 {
		t.Errorf("scheme/listeners: %+v", lb)
	}
	if len(lb.TargetInstances) != 1 || lb.TargetInstances[0] != "i-app" ||
		len(lb.TargetFunctions) != 1 || lb.IPTargets != 1 {
		t.Errorf("targets must be split by the target group's own type (ip targets counted, not joined): %+v", lb)
	}
	if lb.Incomplete != "" {
		t.Errorf("a complete read reported incomplete: %s", lb.Incomplete)
	}
}

// A load balancer whose listeners could not be read must say so — no listeners means no internet edge,
// and unexplained that reads as a closed door.
func TestELBLister_UnreadListenersAreNamed(t *testing.T) {
	lbs, err := (&ELBLister{api: fakeELBAPI{listenersErr: errors.New("AccessDenied")}}).ListLoadBalancers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lbs[0].Incomplete, "listeners") {
		t.Errorf("unread listeners not named: %q", lbs[0].Incomplete)
	}
	res, _ := Fetcher{Buckets: fakeLister{}, LoadBalancers: fakeLBs{out: lbs}}.Fetch(context.Background())
	if !strings.Contains(res.Skipped["elb-details"], "web") {
		t.Errorf("the fetch must carry the partial read into its coverage: %v", res.Skipped)
	}
}

type fakeCFAPI struct{ items []cftypes.DistributionSummary }

func (f fakeCFAPI) ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	return &cloudfront.ListDistributionsOutput{DistributionList: &cftypes.DistributionList{Items: f.items, IsTruncated: aws.Bool(false)}}, nil
}

func signed() *cftypes.TrustedKeyGroups { return &cftypes.TrustedKeyGroups{Enabled: aws.Bool(true)} }
func open() *cftypes.TrustedKeyGroups   { return &cftypes.TrustedKeyGroups{Enabled: aws.Bool(false)} }

// ViewerRestricted needs EVERY behaviour to demand a signature: one open path pattern is an open door.
func TestCloudFrontLister_ViewerRestrictedOnlyWhenEveryBehaviourIsSigned(t *testing.T) {
	mk := func(def *cftypes.TrustedKeyGroups, others ...*cftypes.TrustedKeyGroups) cftypes.DistributionSummary {
		d := cftypes.DistributionSummary{ARN: aws.String("arn:dist"), Enabled: aws.Bool(true),
			Aliases:              &cftypes.Aliases{Items: []string{"files.acme.com"}},
			Origins:              &cftypes.Origins{Items: []cftypes.Origin{{DomainName: aws.String("b.s3.amazonaws.com")}}},
			DefaultCacheBehavior: &cftypes.DefaultCacheBehavior{TrustedKeyGroups: def}}
		cbs := &cftypes.CacheBehaviors{}
		for _, o := range others {
			cbs.Items = append(cbs.Items, cftypes.CacheBehavior{TrustedKeyGroups: o})
		}
		d.CacheBehaviors = cbs
		return d
	}
	for name, tc := range map[string]struct {
		d    cftypes.DistributionSummary
		want bool
	}{
		"all signed":         {mk(signed(), signed()), true},
		"default open":       {mk(open(), signed()), false},
		"one behaviour open": {mk(signed(), signed(), open()), false},
		"nothing configured": {mk(nil), false},
	} {
		ds, err := (&CloudFrontLister{api: fakeCFAPI{items: []cftypes.DistributionSummary{tc.d}}}).ListDistributions(context.Background())
		if err != nil || len(ds) != 1 {
			t.Fatalf("%s: %v %v", name, ds, err)
		}
		if ds[0].ViewerRestricted != tc.want {
			t.Errorf("%s: ViewerRestricted=%v want %v", name, ds[0].ViewerRestricted, tc.want)
		}
		if len(ds[0].Origins) != 1 || len(ds[0].Aliases) != 1 {
			t.Errorf("%s: origins/aliases not carried: %+v", name, ds[0])
		}
	}
}

// End to end through the fetcher: the front doors become a path to a private instance and to a private
// sensitive bucket, and an unread front door is NAMED rather than treated as absent.
func TestFetch_FrontDoorsReachPrivateResources(t *testing.T) {
	res, err := Fetcher{
		Buckets: fakeLister{out: []Bucket{{Name: "exports", Region: "us-east-1", Sensitive: true}}},
		Compute: fakeCompute{
			ins: []Instance{{ID: "i-app"}},
			sgs: []SecurityGroup{{ID: "sg-lb", Rules: []cloudgraph.SGRule{{Proto: "tcp", CIDR: "0.0.0.0/0", PortFrom: 443, PortTo: 443}}}},
		},
		LoadBalancers: fakeLBs{out: []LoadBalancer{{ARN: "arn:lb", DNSName: "web.elb.amazonaws.com", Scheme: "internet-facing",
			SGIDs: []string{"sg-lb"}, Listeners: []Listener{{Port: 443}}, TargetInstances: []string{"i-app"}}}},
		Distributions: fakeDists{out: []Distribution{{ARN: "arn:dist", Enabled: true, Origins: []string{"exports.s3.us-east-1.amazonaws.com"}}}},
	}.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := cloudgraph.Ingest(awsinventory.Build(res.Raw))
	for _, pair := range [][2]string{{cloudgraph.InternetID, "arn:lb"}, {"arn:lb", "i-app"}, {cloudgraph.InternetID, "arn:dist"}, {"arn:dist", "arn:aws:s3:::exports"}} {
		found := false
		for _, e := range s.Edges {
			if e.From == pair[0] && e.To == pair[1] {
				found = true
			}
		}
		if !found {
			t.Errorf("missing edge %s → %s", pair[0], pair[1])
		}
	}

	res, _ = Fetcher{Buckets: fakeLister{}, LoadBalancers: fakeLBs{err: errors.New("AccessDenied")}}.Fetch(context.Background())
	if !strings.Contains(res.Skipped["elb"], "AccessDenied") || !strings.Contains(res.Skipped["cloudfront"], "no CloudFront reader") {
		t.Errorf("unread front doors must be named: %v", res.Skipped)
	}
}

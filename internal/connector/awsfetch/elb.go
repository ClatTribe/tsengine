package awsfetch

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// LoadBalancerReader reads the account's ALBs and NLBs: the front door most web applications sit
// behind, and the hop between the internet and instances that have no public address of their own.
// Every read is a Describe* call, inside ReadOnlyAccess and the cloudsafety session policy.
type LoadBalancerReader interface {
	ListLoadBalancers(ctx context.Context) ([]LoadBalancer, error)
}

// LoadBalancer is one ALB/NLB as the lister reports it.
type LoadBalancer struct {
	ARN, Name, DNSName, Type, Scheme, Region string
	SGIDs                                    []string
	Listeners                                []Listener
	TargetInstances, TargetFunctions         []string
	IPTargets                                int
	// Incomplete names what could not be read for THIS load balancer (its listeners, a target group). A
	// load balancer whose listeners were not read gets no internet edge, which is the conservative
	// answer — and the reason is surfaced so it does not read as a closed door.
	Incomplete string
}

// Listener is one listener port.
type Listener struct {
	Port     int
	Protocol string
}

type elbAPI interface {
	DescribeLoadBalancers(ctx context.Context, in *elb.DescribeLoadBalancersInput, opts ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error)
	DescribeListeners(ctx context.Context, in *elb.DescribeListenersInput, opts ...func(*elb.Options)) (*elb.DescribeListenersOutput, error)
	DescribeTargetGroups(ctx context.Context, in *elb.DescribeTargetGroupsInput, opts ...func(*elb.Options)) (*elb.DescribeTargetGroupsOutput, error)
	DescribeTargetHealth(ctx context.Context, in *elb.DescribeTargetHealthInput, opts ...func(*elb.Options)) (*elb.DescribeTargetHealthOutput, error)
}

// ELBLister reads through the connected read-only role.
type ELBLister struct {
	Region     string
	RoleARN    string
	ExternalID string
	MaxPages   int // per paginated call (default 50)

	api elbAPI // injected in tests
}

func NewELBLister(region, roleARN, externalID string) *ELBLister {
	return &ELBLister{Region: region, RoleARN: roleARN, ExternalID: externalID}
}

func (l *ELBLister) client(ctx context.Context) (elbAPI, error) {
	if l.api != nil {
		return l.api, nil
	}
	cfg, err := assumeRoleConfig(ctx, l.Region, l.RoleARN, l.ExternalID)
	if err != nil {
		return nil, err
	}
	return elb.NewFromConfig(cfg), nil
}

func (l *ELBLister) pages() int {
	if l.MaxPages > 0 {
		return l.MaxPages
	}
	return 50
}

// ListLoadBalancers lists every load balancer, then its listeners and the targets its target groups
// register. Failing to LIST load balancers is an error (the surface is unread); failing to read one load
// balancer's listeners or targets is recorded on that load balancer and the rest still come back.
func (l *ELBLister) ListLoadBalancers(ctx context.Context) ([]LoadBalancer, error) {
	api, err := l.client(ctx)
	if err != nil {
		return nil, err
	}
	var out []LoadBalancer
	var marker *string
	for page := 0; ; page++ {
		if page >= l.pages() {
			return nil, fmt.Errorf("awsfetch: load balancer listing exceeded %d pages; refusing a partial list that would read as complete", l.pages())
		}
		res, err := api.DescribeLoadBalancers(ctx, &elb.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("awsfetch: describe load balancers: %w", err)
		}
		for _, lb := range res.LoadBalancers {
			out = append(out, l.describe(ctx, api, lb))
		}
		if aws.ToString(res.NextMarker) == "" {
			break
		}
		marker = res.NextMarker
	}
	return out, nil
}

func (l *ELBLister) describe(ctx context.Context, api elbAPI, lb elbtypes.LoadBalancer) LoadBalancer {
	arn := aws.ToString(lb.LoadBalancerArn)
	o := LoadBalancer{
		ARN: arn, Name: aws.ToString(lb.LoadBalancerName), DNSName: aws.ToString(lb.DNSName),
		Type: string(lb.Type), Scheme: string(lb.Scheme), Region: l.Region, SGIDs: lb.SecurityGroups,
	}
	var gaps []string
	ls, err := api.DescribeListeners(ctx, &elb.DescribeListenersInput{LoadBalancerArn: aws.String(arn)})
	if err != nil {
		gaps = append(gaps, "listeners: "+err.Error())
	} else {
		for _, li := range ls.Listeners {
			o.Listeners = append(o.Listeners, Listener{Port: int(aws.ToInt32(li.Port)), Protocol: string(li.Protocol)})
		}
		if aws.ToString(ls.NextMarker) != "" {
			gaps = append(gaps, "listeners: more than one page, only the first was read")
		}
	}
	tgs, err := api.DescribeTargetGroups(ctx, &elb.DescribeTargetGroupsInput{LoadBalancerArn: aws.String(arn)})
	if err != nil {
		gaps = append(gaps, "target groups: "+err.Error())
	} else {
		if aws.ToString(tgs.NextMarker) != "" {
			gaps = append(gaps, "target groups: more than one page, only the first was read")
		}
		for _, tg := range tgs.TargetGroups {
			th, err := api.DescribeTargetHealth(ctx, &elb.DescribeTargetHealthInput{TargetGroupArn: tg.TargetGroupArn})
			if err != nil {
				gaps = append(gaps, "targets of "+aws.ToString(tg.TargetGroupArn)+": "+err.Error())
				continue
			}
			for _, d := range th.TargetHealthDescriptions {
				if d.Target == nil {
					continue
				}
				id := aws.ToString(d.Target.Id)
				switch tg.TargetType {
				case elbtypes.TargetTypeEnumInstance:
					o.TargetInstances = append(o.TargetInstances, id)
				case elbtypes.TargetTypeEnumLambda:
					o.TargetFunctions = append(o.TargetFunctions, id)
				default:
					o.IPTargets++
				}
			}
		}
	}
	if len(gaps) > 0 {
		o.Incomplete = fmt.Sprint(gaps)
	}
	return o
}

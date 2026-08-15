package awsfetch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// ec2.go reads compute and its network rules — the surface that decides whether "exposed" is real.
//
// cloudgraph deliberately does NOT treat a public IP as internet-reachable: InternetReachable tests
// whether a security-group rule actually opens the service port to 0.0.0.0/0, by CIDR COVERAGE rather
// than overlap, so a corp-CIDR rule is not internet-open. That check is only as good as the rules fed
// to it — without them every instance looks either uniformly exposed or uniformly safe, and both are
// wrong in the way that matters.
//
// So this reads the ingress rules verbatim and hands them over in cloudgraph's own SGRule shape. It
// makes no reachability judgement itself; that logic already exists and is tested, and duplicating it
// here would give us two answers to the same question.

// ComputeReader is the compute + network surface.
type ComputeReader interface {
	ListCompute(ctx context.Context) ([]Instance, []SecurityGroup, error)
}

// Instance is one compute resource, with the security groups that govern its ingress.
type Instance struct {
	ID       string
	Region   string
	PublicIP bool
	SGIDs    []string
}

// SecurityGroup carries its ingress rules already in cloudgraph's shape.
type SecurityGroup struct {
	ID    string
	Rules []cloudgraph.SGRule
}

// ec2API is the slice of EC2 this needs — describe verbs only.
type ec2API interface {
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

// EC2Lister reads compute through the assumed read-only role.
type EC2Lister struct {
	Region     string
	RoleARN    string
	ExternalID string

	api ec2API // injected in tests
}

// NewEC2Lister builds the live reader. No I/O at construction.
func NewEC2Lister(region, roleARN, externalID string) *EC2Lister {
	return &EC2Lister{Region: region, RoleARN: roleARN, ExternalID: externalID}
}

// ListCompute returns running instances and the security groups referenced by them.
//
// Pagination is followed on both: a truncated instance list hides exposed hosts, and a truncated
// security-group list makes the instances that reference the missing ones look unreachable — the
// quiet false-clean this package exists to avoid.
func (l *EC2Lister) ListCompute(ctx context.Context) ([]Instance, []SecurityGroup, error) {
	api, err := l.client(ctx)
	if err != nil {
		return nil, nil, err
	}

	var instances []Instance
	var token *string
	for {
		res, err := api.DescribeInstances(ctx, &ec2.DescribeInstancesInput{NextToken: token})
		if err != nil {
			return nil, nil, fmt.Errorf("awsfetch: describe instances: %w", err)
		}
		for _, r := range res.Reservations {
			for _, in := range r.Instances {
				// Terminated hosts are not attack surface; including them would inflate the graph
				// with resources nobody can reach.
				if in.State != nil && (in.State.Name == ec2types.InstanceStateNameTerminated ||
					in.State.Name == ec2types.InstanceStateNameShuttingDown) {
					continue
				}
				inst := Instance{
					ID:       aws.ToString(in.InstanceId),
					Region:   l.Region,
					PublicIP: aws.ToString(in.PublicIpAddress) != "",
				}
				for _, g := range in.SecurityGroups {
					if id := aws.ToString(g.GroupId); id != "" {
						inst.SGIDs = append(inst.SGIDs, id)
					}
				}
				instances = append(instances, inst)
			}
		}
		if res.NextToken == nil {
			break
		}
		token = res.NextToken
	}

	var groups []SecurityGroup
	var sgToken *string
	for {
		res, err := api.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{NextToken: sgToken})
		if err != nil {
			return nil, nil, fmt.Errorf("awsfetch: describe security groups: %w", err)
		}
		for _, g := range res.SecurityGroups {
			groups = append(groups, SecurityGroup{
				ID: aws.ToString(g.GroupId), Rules: ingressRules(g.IpPermissions),
			})
		}
		if res.NextToken == nil {
			break
		}
		sgToken = res.NextToken
	}
	return instances, groups, nil
}

// ingressRules flattens EC2 permissions into cloudgraph's SGRule shape.
//
// Only IPv4 CIDRs are emitted today. An IPv6-only opening would therefore not be seen — that is a
// real limitation, recorded here rather than hidden, and the reason it is not simply mapped is that
// cloudgraph.InternetReachable tests coverage of 0.0.0.0/0 specifically; feeding it ::/0 would not
// match and would produce a rule that reads as evaluated when it was not.
func ingressRules(perms []ec2types.IpPermission) []cloudgraph.SGRule {
	var out []cloudgraph.SGRule
	for _, p := range perms {
		proto := aws.ToString(p.IpProtocol)
		from, to := int(aws.ToInt32(p.FromPort)), int(aws.ToInt32(p.ToPort))
		// "-1" is AWS for "every protocol and every port". cloudgraph understands it, so it is
		// passed through verbatim rather than expanded into a guess about which ports that means.
		for _, r := range p.IpRanges {
			cidr := aws.ToString(r.CidrIp)
			if cidr == "" {
				continue
			}
			out = append(out, cloudgraph.SGRule{Proto: proto, CIDR: cidr, PortFrom: from, PortTo: to})
		}
	}
	return out
}

// marshalRules renders rules as the JSON the inventory carries. An empty rule set marshals to an
// empty array rather than null, so a group with no ingress reads as "no openings" rather than
// "unknown" — ParseSGRules treats blank as absent data, which is a different fact.
func marshalRules(rules []cloudgraph.SGRule) string {
	if rules == nil {
		rules = []cloudgraph.SGRule{}
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// client builds the assumed-role EC2 client on first use, or returns the injected test double.
func (l *EC2Lister) client(ctx context.Context) (ec2API, error) {
	if l.api != nil {
		return l.api, nil
	}
	cfg, err := assumeRoleConfig(ctx, l.Region, l.RoleARN, l.ExternalID)
	if err != nil {
		return nil, err
	}
	return ec2.NewFromConfig(cfg), nil
}

package awsremediate

import (
	"context"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// RevokeOpenIngress is the LIVE write for the most common cloud misconfiguration after a public
// bucket: a security group that admits the whole internet. Until now `sg_restrict_ingress` was a
// RUNBOOK — the exact CLI in a ticket — and the customer ran it by hand.
//
// READ, THEN REVOKE EXACTLY WHAT IS OPEN. The writer describes the group first and revokes ONLY the
// world-open source ranges (0.0.0.0/0 and ::/0) of the rules that match — never a corporate CIDR
// that happens to share the same permission, and never a rule the finding did not describe. When
// the finding names a port, only rules covering that port are touched (a protocol of -1 covers
// every port); when it does not, every world-open ingress rule on the group goes. A group with NO
// world-open rule is an ERROR, not a success: the finding may be stale, and "applied" over a
// no-op would tell the customer a fix landed that changed nothing.
//
// Revoking a rule is REVERSIBLE (re-add it), which is why it sits at the same gate as blocking
// public access on a bucket. It is still a change that can cut off a client, so it is HITL-gated
// like every other cloud write. Needs ec2:DescribeSecurityGroups + ec2:RevokeSecurityGroupIngress
// on the WRITE role.
type ec2SecurityGroupAPI interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	RevokeSecurityGroupIngress(ctx context.Context, params *ec2.RevokeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error)
}

var securityGroupIDRe = regexp.MustCompile(`^sg-[0-9a-f]{8,17}$`)

const (
	worldV4 = "0.0.0.0/0"
	worldV6 = "::/0"
)

func (w *S3Writer) RevokeOpenIngress(ctx context.Context, groupID string, port int) error {
	if !securityGroupIDRe.MatchString(groupID) {
		return fmt.Errorf("awsremediate: %q is not a security group id", groupID)
	}
	client, err := w.ec2Client(ctx)
	if err != nil {
		return fmt.Errorf("awsremediate: build ec2 client: %w", err)
	}
	desc, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{groupID}})
	if err != nil {
		return fmt.Errorf("awsremediate: DescribeSecurityGroups(%s): %w", groupID, err)
	}
	if len(desc.SecurityGroups) != 1 {
		return fmt.Errorf("awsremediate: security group %s not found", groupID)
	}
	perms := OpenIngress(desc.SecurityGroups[0].IpPermissions, port)
	if len(perms) == 0 {
		if port > 0 {
			return fmt.Errorf("awsremediate: %s has no ingress rule open to the internet on port %d — nothing revoked (the finding may be stale)", groupID, port)
		}
		return fmt.Errorf("awsremediate: %s has no ingress rule open to the internet — nothing revoked (the finding may be stale)", groupID)
	}
	if _, err := client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId: aws.String(groupID), IpPermissions: perms,
	}); err != nil {
		return fmt.Errorf("awsremediate: RevokeSecurityGroupIngress(%s): %w", groupID, err)
	}
	return nil
}

// OpenIngress returns, for each ingress permission that admits the whole internet (and covers
// `port` when port > 0), a permission carrying ONLY its world-open ranges — the exact argument for
// RevokeSecurityGroupIngress. Exported so the selection is testable apart from the SDK call.
func OpenIngress(perms []ec2types.IpPermission, port int) []ec2types.IpPermission {
	var out []ec2types.IpPermission
	for _, p := range perms {
		if port > 0 && !covers(p, port) {
			continue
		}
		var v4 []ec2types.IpRange
		for _, r := range p.IpRanges {
			if aws.ToString(r.CidrIp) == worldV4 {
				v4 = append(v4, ec2types.IpRange{CidrIp: r.CidrIp})
			}
		}
		var v6 []ec2types.Ipv6Range
		for _, r := range p.Ipv6Ranges {
			if aws.ToString(r.CidrIpv6) == worldV6 {
				v6 = append(v6, ec2types.Ipv6Range{CidrIpv6: r.CidrIpv6})
			}
		}
		if len(v4) == 0 && len(v6) == 0 {
			continue
		}
		out = append(out, ec2types.IpPermission{IpProtocol: p.IpProtocol, FromPort: p.FromPort, ToPort: p.ToPort, IpRanges: v4, Ipv6Ranges: v6})
	}
	return out
}

// covers reports whether the permission admits traffic on the port: protocol -1 is every port;
// a nil range (ICMP, or an all-ports rule for the protocol) is treated as covering it.
func covers(p ec2types.IpPermission, port int) bool {
	if aws.ToString(p.IpProtocol) == "-1" || p.FromPort == nil || p.ToPort == nil {
		return true
	}
	from, to := int(aws.ToInt32(p.FromPort)), int(aws.ToInt32(p.ToPort))
	if from == -1 && to == -1 {
		return true
	}
	return from <= port && port <= to
}

func (w *S3Writer) ec2Client(ctx context.Context) (ec2SecurityGroupAPI, error) {
	if w.newEC2 != nil {
		return w.newEC2(ctx)
	}
	region := w.Region
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	if w.RoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), w.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			if w.ExternalID != "" {
				o.ExternalID = aws.String(w.ExternalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return ec2.NewFromConfig(cfg), nil
}

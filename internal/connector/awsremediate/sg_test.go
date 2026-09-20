package awsremediate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeEC2 struct {
	groups  []ec2types.SecurityGroup
	descErr error
	revoked *ec2.RevokeSecurityGroupIngressInput
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if f.descErr != nil {
		return nil, f.descErr
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.groups}, nil
}

func (f *fakeEC2) RevokeSecurityGroupIngress(_ context.Context, in *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	f.revoked = in
	return &ec2.RevokeSecurityGroupIngressOutput{}, nil
}

func mixedGroup() ec2types.SecurityGroup {
	return ec2types.SecurityGroup{GroupId: aws.String("sg-0abc12345"), IpPermissions: []ec2types.IpPermission{
		// ssh: world AND a corporate range in the SAME permission — only the world range may go.
		{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}, {CidrIp: aws.String("10.1.0.0/16")}},
			Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}}},
		// https from a partner only — untouched.
		{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("203.0.113.0/24")}}},
		// rdp: world-open on a different port.
		{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(3389), ToPort: aws.Int32(3389), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},
	}}
}

// The writer reads the group and revokes ONLY the world-open ranges of the rules covering the
// named port — the corporate range sharing the ssh rule and the partner-only https rule survive.
func TestRevokeOpenIngress_RevokesOnlyTheWorldRangesOnThePort(t *testing.T) {
	api := &fakeEC2{groups: []ec2types.SecurityGroup{mixedGroup()}}
	w := &S3Writer{newEC2: func(context.Context) (ec2SecurityGroupAPI, error) { return api, nil }}
	if err := w.RevokeOpenIngress(context.Background(), "sg-0abc12345", 22); err != nil {
		t.Fatal(err)
	}
	if api.revoked == nil || aws.ToString(api.revoked.GroupId) != "sg-0abc12345" || len(api.revoked.IpPermissions) != 1 {
		t.Fatalf("revoke: %+v", api.revoked)
	}
	p := api.revoked.IpPermissions[0]
	if aws.ToInt32(p.FromPort) != 22 || len(p.IpRanges) != 1 || aws.ToString(p.IpRanges[0].CidrIp) != "0.0.0.0/0" || len(p.Ipv6Ranges) != 1 {
		t.Errorf("must revoke exactly the world v4 + v6 ranges of the ssh rule, got %+v", p)
	}

	// No port named → every world-open rule (ssh + rdp), still never the partner or corp ranges.
	api.revoked = nil
	if err := w.RevokeOpenIngress(context.Background(), "sg-0abc12345", 0); err != nil {
		t.Fatal(err)
	}
	if len(api.revoked.IpPermissions) != 2 {
		t.Errorf("no port → both world-open rules: %+v", api.revoked.IpPermissions)
	}
	for _, p := range api.revoked.IpPermissions {
		for _, r := range p.IpRanges {
			if aws.ToString(r.CidrIp) != "0.0.0.0/0" {
				t.Errorf("a non-world range was revoked: %s", aws.ToString(r.CidrIp))
			}
		}
	}
}

// Nothing world-open on the port → an ERROR, never a silent "applied"; a bad id is refused before
// any call; a describe failure surfaces as itself.
func TestRevokeOpenIngress_RefusesWhenThereIsNothingToRevoke(t *testing.T) {
	api := &fakeEC2{groups: []ec2types.SecurityGroup{mixedGroup()}}
	w := &S3Writer{newEC2: func(context.Context) (ec2SecurityGroupAPI, error) { return api, nil }}
	err := w.RevokeOpenIngress(context.Background(), "sg-0abc12345", 443)
	if err == nil || !strings.Contains(err.Error(), "nothing revoked") || api.revoked != nil {
		t.Errorf("443 is partner-only: must refuse without calling revoke, got err=%v revoked=%v", err, api.revoked)
	}
	if err := w.RevokeOpenIngress(context.Background(), "not-a-group", 22); err == nil || !strings.Contains(err.Error(), "not a security group id") {
		t.Errorf("bad id: %v", err)
	}
	w2 := &S3Writer{newEC2: func(context.Context) (ec2SecurityGroupAPI, error) {
		return &fakeEC2{descErr: errors.New("UnauthorizedOperation: ec2:DescribeSecurityGroups")}, nil
	}}
	if err := w2.RevokeOpenIngress(context.Background(), "sg-0abc12345", 22); err == nil || !strings.Contains(err.Error(), "UnauthorizedOperation") {
		t.Errorf("describe failure must surface: %v", err)
	}
}

// An all-traffic rule (-1) covers every port; an explicit range is honoured.
func TestOpenIngress_AllTrafficCoversEveryPort(t *testing.T) {
	perms := []ec2types.IpPermission{
		{IpProtocol: aws.String("-1"), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},
		{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(8000), ToPort: aws.Int32(9000), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},
	}
	if got := OpenIngress(perms, 5432); len(got) != 1 || aws.ToString(got[0].IpProtocol) != "-1" {
		t.Errorf("5432 is covered only by the all-traffic rule: %+v", got)
	}
	if got := OpenIngress(perms, 8080); len(got) != 2 {
		t.Errorf("8080 is covered by both: %+v", got)
	}
}

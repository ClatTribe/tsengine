package cloudquery

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

// ToInventory resolves a CloudQuery dataset into the engine's inventory graph.
// This is the INGEST SOURCE doing effective-permissions evaluation — the job the
// cloudgraph.Inventory seam expects its source to have already done. Because it
// gates edges on the REAL policy state (trust policies + permission boundaries),
// the resulting graph does not over-approximate, which is what makes the engine
// correctly downgrade the boundary-blocked / trust-denied findings (the cases the
// held-out bench showed a naive ingest gets wrong).
//
// Resolution rules:
//   - network_reach internet→ec2  iff the instance has a public IP AND a security
//     group open to 0.0.0.0/0.
//   - network_reach internet→bucket iff the bucket is public (a public jewel is
//     directly reachable).
//   - runs_as ec2→role from the instance profile.
//   - has_access role→bucket iff effective perms (attached ∧ boundary) allow
//     s3:GetObject on the bucket.
//   - assume_role A→B iff A's effective perms allow sts:AssumeRole on B AND B's
//     TRUST policy permits A (the double gate).
//   - privesc role→admin iff effective perms (attached ∧ boundary) enable a known
//     escalation technique.
func ToInventory(t *Tables) cloudgraph.Inventory {
	inv := cloudgraph.Inventory{AccountID: "cloudquery-emulated", Provider: "aws"}

	// resources
	for _, b := range t.S3Buckets {
		sens := sensitivity(b.Tags)
		kind := cloudgraph.KindResource
		if sens != cloudgraph.SensNone {
			kind = cloudgraph.KindData
		}
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: b.ARN, Kind: kind, Type: "AWS::S3::Bucket", Name: b.Name, Region: b.Region,
			Public: bucketPublic(b), Sensitive: sens,
		})
	}
	for _, e := range t.EC2Instances {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: e.ARN, Kind: cloudgraph.KindResource, Type: "AWS::EC2::Instance", Name: e.Name,
			Public: e.PublicIPAddress != "",
		})
	}
	for _, r := range t.IAMRoles {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: r.ARN, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: r.Name,
		})
	}

	sgOpen := map[string]bool{}
	for _, sg := range t.SecurityGroups {
		sgOpen[sg.ID] = sg.OpenIngressFromInternet
	}

	// network reachability
	for _, e := range t.EC2Instances {
		if e.PublicIPAddress == "" {
			continue
		}
		for _, sgid := range e.SecurityGroupIDs {
			if sgOpen[sgid] {
				inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: e.ARN})
				break
			}
		}
	}
	for _, b := range t.S3Buckets {
		if bucketPublic(b) {
			inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: b.ARN})
		}
	}

	// runs_as
	for _, e := range t.EC2Instances {
		if e.IAMInstanceProfileRoleARN != "" {
			inv.RunsAs = append(inv.RunsAs, cloudgraph.InvRunsAs{Compute: e.ARN, Principal: e.IAMInstanceProfileRoleARN})
		}
	}

	// IAM effective-permission resolution
	var anyPrivesc bool
	for _, r := range t.IAMRoles {
		attached := parseDocs(r.InlinePolicies)
		boundary := parseDoc(r.PermissionsBoundary)

		// has_access role→bucket
		for _, b := range t.S3Buckets {
			if effectiveAllows("s3:GetObject", b.ARN, attached, boundary) ||
				effectiveAllows("s3:GetObject", b.ARN+"/*", attached, boundary) {
				inv.Grants = append(inv.Grants, cloudgraph.InvGrant{Principal: r.ARN, Resource: b.ARN})
			}
		}

		// assume_role A→B: A may call AssumeRole on B AND B trusts A
		for _, b := range t.IAMRoles {
			if b.ARN == r.ARN {
				continue
			}
			if !effectiveAllows("sts:AssumeRole", b.ARN, attached, boundary) {
				continue
			}
			if trust := parseDoc(b.AssumeRolePolicyDocument); trust != nil {
				if ok, _ := cloudiam.Allows("sts:AssumeRole", r.ARN, trust); ok {
					inv.Trusts = append(inv.Trusts, cloudgraph.InvTrust{Principal: r.ARN, Role: b.ARN})
				}
			}
		}

		// privesc role→admin (effective, boundary-aware)
		can := func(a string) bool { return effectiveAllows(a, "*", attached, boundary) }
		if techs := cloudiam.DetectPrivesc(can); len(techs) > 0 {
			anyPrivesc = true
			names := make([]string, len(techs))
			for i, tc := range techs {
				names[i] = tc.Name
			}
			inv.Privescs = append(inv.Privescs, cloudgraph.InvPrivesc{
				Principal: r.ARN, Target: cloudgraph.AdminID, Detail: strings.Join(names, ","),
			})
		}
	}
	if anyPrivesc {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: cloudgraph.AdminID, Kind: cloudgraph.KindPrincipal, Name: "effective-admin", Privileged: true,
		})
	}
	return inv
}

// effectiveAllows implements AWS effective-permission semantics for our subset:
// the action must be permitted by the identity (attached) policies AND, if a
// permission boundary is present, by the boundary too (intersection). An explicit
// Deny in either wins (handled inside cloudiam.Allows).
func effectiveAllows(action, resource string, attached []*cloudiam.Document, boundary *cloudiam.Document) bool {
	ok, _ := cloudiam.Allows(action, resource, attached...)
	if !ok {
		return false
	}
	if boundary == nil {
		return true
	}
	bok, _ := cloudiam.Allows(action, resource, boundary)
	return bok
}

func bucketPublic(b S3Bucket) bool {
	return b.PolicyAllowsPublic || (!b.BlockPublicACLs && !b.BlockPublicPolicy)
}

func sensitivity(tags map[string]string) cloudgraph.Sensitivity {
	switch strings.ToLower(tags["classification"]) {
	case "pii", "phi", "secret", "confidential", "restricted":
		return cloudgraph.SensHigh
	case "internal", "low":
		return cloudgraph.SensLow
	default:
		return cloudgraph.SensNone
	}
}

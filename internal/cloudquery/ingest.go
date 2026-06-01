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
	for _, u := range t.IAMUsers {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: u.ARN, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::User", Name: u.Name,
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

	// IAM resolution via the full AWS decision (cloudiam.Authorize): identity ∧
	// boundary, the org SCP ceiling, RESOURCE-based (bucket) policies, and
	// condition evaluation. Account-level inputs computed once.
	scps := parseDocs(t.SCPs)
	bucketPolicy := map[string]*cloudiam.Document{}
	for _, b := range t.S3Buckets {
		bucketPolicy[b.ARN] = parseDoc(b.Policy)
	}
	var anyPrivesc bool

	for _, r := range t.IAMRoles {
		identity := parseDocs(r.InlinePolicies)
		boundary := parseDoc(r.PermissionsBoundary)

		// has_access role→bucket (identity OR bucket policy, gated by SCP/boundary).
		for _, b := range t.S3Buckets {
			if ok, cond := canReadBucket(r.ARN, b.ARN, identity, boundary, scps, bucketPolicy[b.ARN]); ok {
				inv.Grants = append(inv.Grants, cloudgraph.InvGrant{Principal: r.ARN, Resource: b.ARN, Condition: condStr(cond)})
			}
		}
		// assume_role A→B: A may call AssumeRole on B (SCP/boundary-aware) AND B's
		// trust policy permits A. Skip the whole O(n) inner scan for the many roles
		// that cannot call sts:AssumeRole at all (keeps large accounts near-linear).
		if canPossiblyAssume(identity) {
			for _, b := range t.IAMRoles {
				if b.ARN == r.ARN {
					continue
				}
				aOK, _ := cloudiam.Permits(cloudiam.Request{Principal: r.ARN, Action: "sts:AssumeRole", Resource: b.ARN},
					cloudiam.PolicySet{Identity: identity, Boundary: boundary, SCPs: scps, SameAccount: true})
				if !aOK {
					continue
				}
				if trust := parseDoc(b.AssumeRolePolicyDocument); trust != nil {
					if ok, _ := cloudiam.Allows("sts:AssumeRole", r.ARN, trust); ok {
						inv.Trusts = append(inv.Trusts, cloudgraph.InvTrust{Principal: r.ARN, Role: b.ARN})
					}
				}
			}
		}
		// privesc role→admin (SCP/boundary-aware effective perms).
		if names, ok := detectPrivesc(r.ARN, identity, boundary, scps); ok {
			anyPrivesc = true
			inv.Privescs = append(inv.Privescs, cloudgraph.InvPrivesc{Principal: r.ARN, Target: cloudgraph.AdminID, Detail: names})
		}
	}

	// IAM users: has_access + privesc (a user is not assumed).
	for _, u := range t.IAMUsers {
		identity := parseDocs(u.InlinePolicies)
		boundary := parseDoc(u.PermissionsBoundary)
		for _, b := range t.S3Buckets {
			if ok, cond := canReadBucket(u.ARN, b.ARN, identity, boundary, scps, bucketPolicy[b.ARN]); ok {
				inv.Grants = append(inv.Grants, cloudgraph.InvGrant{Principal: u.ARN, Resource: b.ARN, Condition: condStr(cond)})
			}
		}
		if names, ok := detectPrivesc(u.ARN, identity, boundary, scps); ok {
			anyPrivesc = true
			inv.Privescs = append(inv.Privescs, cloudgraph.InvPrivesc{Principal: u.ARN, Target: cloudgraph.AdminID, Detail: names})
		}
	}

	if anyPrivesc {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: cloudgraph.AdminID, Kind: cloudgraph.KindPrincipal, Name: "effective-admin", Privileged: true,
		})
	}
	return inv
}

// canReadBucket resolves has_access via the full AWS decision: s3:GetObject is
// granted if the identity policy OR the bucket's RESOURCE policy allows it (same
// account), subject to the SCP and permission-boundary ceilings. The second
// return is true when the grant is gated by an unresolved condition.
func canReadBucket(principal, bucketARN string, identity []*cloudiam.Document, boundary *cloudiam.Document, scps []*cloudiam.Document, resourcePolicy *cloudiam.Document) (allowed, conditional bool) {
	ps := cloudiam.PolicySet{Identity: identity, Boundary: boundary, SCPs: scps, ResourcePolicy: resourcePolicy, SameAccount: true}
	for _, res := range []string{bucketARN, bucketARN + "/*"} {
		if ok, cond := cloudiam.Permits(cloudiam.Request{Principal: principal, Action: "s3:GetObject", Resource: res}, ps); ok {
			return true, cond
		}
	}
	return false, false
}

// detectPrivesc evaluates the privesc techniques a principal can perform under
// its effective permissions, honouring the SCP + boundary ceilings (an SCP that
// denies the escalation action blocks the privesc edge).
func detectPrivesc(principal string, identity []*cloudiam.Document, boundary *cloudiam.Document, scps []*cloudiam.Document) (string, bool) {
	can := func(a string) bool {
		ok, _ := cloudiam.Permits(cloudiam.Request{Principal: principal, Action: a, Resource: "*"},
			cloudiam.PolicySet{Identity: identity, Boundary: boundary, SCPs: scps, SameAccount: true})
		return ok
	}
	techs := cloudiam.DetectPrivesc(can)
	if len(techs) == 0 {
		return "", false
	}
	names := make([]string, len(techs))
	for i, tc := range techs {
		names[i] = tc.Name
	}
	return strings.Join(names, ","), true
}

func condStr(conditional bool) string {
	if conditional {
		return "runtime condition (needs live validation)"
	}
	return ""
}

// canPossiblyAssume is a cheap, permissive pre-filter: does any Allow statement
// plausibly grant sts:AssumeRole? Used to skip the O(n) assume-resolution scan for
// the many roles that cannot assume anything (keeps large accounts near-linear).
// When unsure it returns true (never skips a role that might assume).
func canPossiblyAssume(identity []*cloudiam.Document) bool {
	for _, d := range identity {
		if d == nil {
			continue
		}
		for _, st := range d.Statement {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			for _, a := range st.Action {
				if a == "*" || a == "sts:*" || strings.EqualFold(a, "sts:AssumeRole") {
					return true
				}
			}
		}
	}
	return false
}

// effectiveAllows implements AWS effective-permission semantics for our subset:
// the action must be permitted by the identity (attached) policies AND, if a
// permission boundary is present, by the boundary too (intersection). An explicit
// Deny in either wins (handled inside cloudiam.Allows). Retained for the
// generator's independent answer-key checks (dataset.go).
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

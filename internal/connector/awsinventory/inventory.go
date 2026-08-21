// Package awsinventory collects a connected AWS account's IAM + network + storage state and maps it into a
// cloudgraph.Inventory — the attack-path engine's FUEL. It is the live half of the cross-surface wedge: the
// engine already builds attack paths from a POSTED inventory (cloudgraph.Ingest); this turns the onboarded
// AWS read-role into that inventory automatically, so "find the attack path across code, cloud, and SaaS"
// works on a real account, not only the demo. The repo's leaked-key/ARN findings bridge to the principal +
// resource ARNs this collector emits (the cross-surface join in internal/correlate), and the Trusts/Reaches
// it emits are the cloud-internal path to cloud root.
//
// The AWS SDK is isolated in this package (core `connector` + `cloudgraph` stay SDK-free), mirroring the
// *remediate packages. The MAPPER (Build) is pure, grounded (§10), and unit-tested: it asserts only what the
// raw state proves — a trust edge only where a role's trust policy names a concrete principal, an
// internet→resource reach only where the resource is public AND its security group actually opens the
// service port to 0.0.0.0/0 (reusing cloudgraph.InternetReachable, the same CIDR-coverage eval the engine
// prunes with). A clean account yields a minimal graph with no internet edges. The live list-/describe-
// calls (a real Fetcher over a scoped STS-assumed role) are the credential-gated half.
package awsinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

// RawAWS mirrors the SUBSET of AWS list-/describe- output the mapper reads. Pure data (no SDK types) so
// Build is unit-testable with fixtures and the SDK stays behind Fetcher.
// JSON tags make RawAWS a wire format too: an external collector with AWS creds (a CI job, the customer's
// own script) can POST this raw shape to /v1/cloud/inventory and the platform maps + stores it — the same
// posted-snapshot pattern as /v1/osint/ingest, with the live SDK fetch as the gated alternative.
type RawAWS struct {
	AccountID string             `json:"account_id"`
	Users     []RawIAMUser       `json:"users,omitempty"`
	Roles     []RawIAMRole       `json:"roles,omitempty"`
	SGs       []RawSecurityGroup `json:"security_groups,omitempty"`
	Instances []RawInstance      `json:"instances,omitempty"`
	Buckets   []RawBucket        `json:"buckets,omitempty"`
	// Grants are principal -> resource access facts. Without them an inventory has identities and
	// data but nothing connecting the two, so no path can ever run from a foothold to a crown
	// jewel. They are asserted by the fetcher (policy evaluation), never inferred here: guessing
	// which principals can read which buckets is exactly the fabricated-path failure mode.
	Grants []RawGrant `json:"grants,omitempty"`
}

// RawGrant records that a principal holds access to a resource.
type RawGrant struct {
	Principal string `json:"principal"`
	Resource  string `json:"resource"`
	// Condition carries an IAM condition the grant depends on (MFA, a source IP, a tag). It is
	// passed through rather than dropped, because a conditional grant is not the same claim as an
	// unconditional one and the graph gates on exactly this (ADR 0002).
	Condition string `json:"condition,omitempty"`
}

// RawIAMUser / RawIAMRole carry the identity + a fetcher-resolved Admin flag (an attached/inline policy
// grants admin-equivalent — AdministratorAccess or *:*). The role also carries its verbatim trust policy.
type RawIAMUser struct {
	ARN   string `json:"arn"`
	Name  string `json:"name,omitempty"`
	Admin bool   `json:"admin,omitempty"`
	// PoliciesJSON / BoundaryJSON mirror RawIAMRole — see there for why the boundary is
	// carried and why empty means "none", not "denies everything".
	PoliciesJSON []string `json:"policies,omitempty"`
	BoundaryJSON string   `json:"permission_boundary,omitempty"`
	// AccessKeyIDs are the user's long-lived access keys (iam:ListAccessKeys). Optional, and the
	// honest gate on the code->cloud join: without them a key leaked in a repository cannot be
	// matched to the principal it becomes, so the two surfaces stay disconnected rather than
	// being joined on a guess.
	AccessKeyIDs []string `json:"access_key_ids,omitempty"`
}
type RawIAMRole struct {
	ARN             string `json:"arn"`
	Name            string `json:"name,omitempty"`
	Admin           bool   `json:"admin,omitempty"`
	TrustPolicyJSON string `json:"trust_policy,omitempty"`
	// PoliciesJSON are the role's attached + inline policy DOCUMENTS. Without them the
	// only privilege signal is the Admin boolean, which answers "is this already admin"
	// and not "can this BECOME admin" — and the second is the whole attack path.
	PoliciesJSON []string `json:"policies,omitempty"`
	// BoundaryJSON is the permission boundary document, a CEILING rather than a grant.
	// Empty means the principal has none, which is NOT the same as one that permits
	// nothing: reading unfetched data as a deny-everything boundary would silently erase
	// every escalation in an account we simply have not read.
	BoundaryJSON string `json:"permission_boundary,omitempty"`
}

// RawSecurityGroup carries the normalized ingress rules (a JSON array of cloudgraph.SGRule) for one SG.
type RawSecurityGroup struct {
	ID          string `json:"id"`
	IngressJSON string `json:"ingress,omitempty"`
}

// RawInstance is a compute resource; PublicIP + SGIDs + ServicePort drive the grounded reachability eval.
type RawInstance struct {
	ID           string   `json:"id"`
	Region       string   `json:"region,omitempty"`
	PublicIP     bool     `json:"public_ip,omitempty"`
	SGIDs        []string `json:"security_group_ids,omitempty"`
	ServicePort  int      `json:"service_port,omitempty"`  // primary listening port; 0 = unknown → no internet edge
	ServiceProto string   `json:"service_proto,omitempty"` // "tcp" (default) | "udp"
	// DNSNames are the hostnames resolving to this instance (public DNS, an ELB/CloudFront alias in
	// front of it). Optional, and the honest gate on the web->cloud join: without them a pentest
	// target hostname cannot be matched to the resource it runs on, so the two surfaces stay
	// disconnected rather than being joined on a name that merely looks similar.
	DNSNames []string `json:"dns_names,omitempty"`
	// RoleARN is the instance profile's role — the identity the workload executes with. Without it
	// a compute resource is a dead end in the graph: an attacker who lands on the box inherits its
	// role, and that inheritance is the step every host-to-data path runs through.
	RoleARN string `json:"role_arn,omitempty"`
}

// RawBucket is an object store; Public + Sensitive are fetcher-resolved (public-access-block / tags).
type RawBucket struct {
	ARN       string `json:"arn,omitempty"`
	Name      string `json:"name"`
	Region    string `json:"region,omitempty"`
	Public    bool   `json:"public,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

// Build maps the raw AWS subset into a cloudgraph.Inventory. Pure + grounded (§10).
func Build(raw RawAWS) cloudgraph.Inventory {
	inv := cloudgraph.Inventory{AccountID: raw.AccountID, Provider: "aws"}

	for _, u := range raw.Users {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: u.ARN, Kind: cloudgraph.KindPrincipal, Type: "iam_user", Name: u.Name, Privileged: u.Admin,
			AccessKeyIDs: u.AccessKeyIDs,
		})
		addPrivesc(&inv, u.ARN, u.PoliciesJSON, u.BoundaryJSON)
	}
	for _, r := range raw.Roles {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: r.ARN, Kind: cloudgraph.KindPrincipal, Type: "iam_role", Name: r.Name, Privileged: r.Admin,
		})
		for _, p := range trustPrincipals(r.TrustPolicyJSON) {
			inv.Trusts = append(inv.Trusts, cloudgraph.InvTrust{Principal: p, Role: r.ARN})
		}
		addPrivesc(&inv, r.ARN, r.PoliciesJSON, r.BoundaryJSON)
	}
	// The synthetic admin node is declared only when something can actually reach it. An
	// account with no escalation path should not carry a node implying one exists.
	if len(inv.Privescs) > 0 {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: cloudgraph.AdminID, Kind: cloudgraph.KindPrincipal, Type: "effective_admin",
			Name: "effective-admin", Privileged: true,
		})
	}

	sgByID := make(map[string]RawSecurityGroup, len(raw.SGs))
	for _, sg := range raw.SGs {
		sgByID[sg.ID] = sg
	}
	for _, in := range raw.Instances {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: in.ID, Kind: cloudgraph.KindResource, Type: "ec2_instance", Region: in.Region, Public: in.PublicIP,
			DNSNames: in.DNSNames,
		})
		if r := strings.TrimSpace(in.RoleARN); r != "" {
			inv.RunsAs = append(inv.RunsAs, cloudgraph.InvRunsAs{Compute: in.ID, Principal: r})
		}
		if !in.PublicIP || in.ServicePort == 0 {
			continue // grounded: no public IP / unknown port → never assert internet reachability
		}
		var rules []cloudgraph.SGRule
		for _, id := range in.SGIDs {
			rs, err := cloudgraph.ParseSGRules(sgByID[id].IngressJSON)
			if err != nil {
				continue
			}
			rules = append(rules, rs...)
		}
		proto := in.ServiceProto
		if proto == "" {
			proto = "tcp"
		}
		if cloudgraph.InternetReachable(rules, in.ServicePort, proto) {
			inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: in.ID})
		}
	}

	for _, b := range raw.Buckets {
		kind := cloudgraph.KindResource
		sens := cloudgraph.SensNone
		if b.Sensitive {
			kind = cloudgraph.KindData // a data store carries the sensitivity / crown-jewel signal
			sens = cloudgraph.SensHigh
		}
		id := b.ARN
		if id == "" {
			id = "arn:aws:s3:::" + b.Name
		}
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: id, Kind: kind, Type: "s3_bucket", Name: b.Name, Region: b.Region, Public: b.Public, Sensitive: sens,
		})
		if b.Public {
			inv.Reaches = append(inv.Reaches, cloudgraph.InvReach{From: cloudgraph.InternetID, To: id})
		}
	}

	for _, gr := range raw.Grants {
		// Both ends must be named. A half-specified grant would otherwise create an edge to an
		// empty node id, which reads downstream as a real relationship to nothing.
		if strings.TrimSpace(gr.Principal) == "" || strings.TrimSpace(gr.Resource) == "" {
			continue
		}
		inv.Grants = append(inv.Grants, cloudgraph.InvGrant{
			Principal: gr.Principal, Resource: gr.Resource, Condition: gr.Condition,
		})
	}
	return inv
}

// Fetcher pulls the raw AWS state for one account. The live implementation (real list-/describe- calls over
// a scoped STS-assumed read role) is the credential-gated half; tests inject a fake.
type Fetcher interface {
	Fetch(ctx context.Context) (RawAWS, error)
}

// Collect runs the fetcher and maps the result into the engine's Inventory.
func Collect(ctx context.Context, f Fetcher) (cloudgraph.Inventory, error) {
	if f == nil {
		return cloudgraph.Inventory{}, fmt.Errorf("awsinventory: no fetcher configured")
	}
	raw, err := f.Fetch(ctx)
	if err != nil {
		return cloudgraph.Inventory{}, fmt.Errorf("awsinventory: fetch: %w", err)
	}
	return Build(raw), nil
}

// --- trust-policy parsing (tolerant of AWS's string-or-array policy shapes) ---

// trustPrincipals returns every concrete principal ARN an IAM assume-role trust policy lets assume the role
// (Effect "Allow", Principal.AWS). Grounded: nothing on an empty/unparseable doc; a bare "*" or a Service
// principal yields no edge (no specific principal node to bridge from).
func trustPrincipals(doc string) []string {
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	var d trustDoc
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		return nil
	}
	var out []string
	for _, st := range d.statements() {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		out = append(out, st.principalAWS()...)
	}
	return out
}

type trustDoc struct {
	Statement json.RawMessage `json:"Statement"`
}
type trustStmt struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
}

// statements decodes Statement, which AWS allows to be a single object OR an array.
func (d trustDoc) statements() []trustStmt {
	if len(d.Statement) == 0 {
		return nil
	}
	var arr []trustStmt
	if err := json.Unmarshal(d.Statement, &arr); err == nil {
		return arr
	}
	var one trustStmt
	if err := json.Unmarshal(d.Statement, &one); err == nil {
		return []trustStmt{one}
	}
	return nil
}

// principalAWS extracts Principal.AWS (string or array); a bare-string Principal (e.g. "*") yields nothing.
func (s trustStmt) principalAWS() []string {
	if len(s.Principal) == 0 {
		return nil
	}
	var obj struct {
		AWS json.RawMessage `json:"AWS"`
	}
	if err := json.Unmarshal(s.Principal, &obj); err == nil && len(obj.AWS) > 0 {
		return stringOrArray(obj.AWS)
	}
	return nil
}

// stringOrArray decodes a JSON value that AWS allows to be either a string or an array of strings.
func stringOrArray(r json.RawMessage) []string {
	var arr []string
	if err := json.Unmarshal(r, &arr); err == nil {
		return arr
	}
	var s string
	if err := json.Unmarshal(r, &s); err == nil && s != "" {
		return []string{s}
	}
	return nil
}

// addPrivesc turns a principal's IAM policy documents into privesc edges, evaluating the
// PERMISSION BOUNDARY as AWS does (effective = attached ∧ boundary).
//
// This is the wiring the held-out generalization benchmark asked for. Before it, no
// production ingest path produced a policy-derived escalation edge at all: a principal
// was marked Privileged from an `Admin` boolean, which answers "is this already admin"
// and never "can this BECOME admin" — so the attack path the product exists to find was
// invisible on real accounts while passing on synthetic ones.
//
// GROUNDED (§10) in both directions:
//
//   - No policy documents → NO edges. That is "we did not read the policies", not "there
//     is no escalation", and the two must not be confused. The fetch layer reports the
//     omission in its coverage line; inventing an edge here would be worse than silence.
//   - A boundary that blocks the escalation → NO edge, because AWS would block it. A
//     false path to admin sends someone to sever a route that was never open while the
//     real one stays open.
//   - An escalation reachable only through a CONDITIONED grant is marked Condition, so a
//     path through it reads config-possible rather than confirmed (ADR 0002).
func addPrivesc(inv *cloudgraph.Inventory, principal string, policiesJSON []string, boundaryJSON string) {
	if principal == "" || len(policiesJSON) == 0 {
		return
	}
	docs := make([]*cloudiam.Document, 0, len(policiesJSON))
	for _, js := range policiesJSON {
		if strings.TrimSpace(js) == "" {
			continue
		}
		d, err := cloudiam.Parse([]byte(js))
		if err != nil || d == nil {
			// An unreadable policy is not an absent one. Skipping it can only UNDER-report,
			// which is the safe direction here; over-reporting would fabricate a path.
			continue
		}
		docs = append(docs, d)
	}
	if len(docs) == 0 {
		return
	}
	var boundary *cloudiam.Document
	if strings.TrimSpace(boundaryJSON) != "" {
		if b, err := cloudiam.Parse([]byte(boundaryJSON)); err == nil {
			boundary = b
		}
		// A boundary we cannot parse is left nil rather than treated as denying
		// everything — see RawIAMRole.BoundaryJSON.
	}

	ps := cloudiam.PolicySet{Identity: docs, Boundary: boundary, SameAccount: true}
	can := func(a string) bool {
		dec, _ := cloudiam.Authorize(cloudiam.Request{Principal: principal, Action: a, Resource: "*"}, ps)
		return dec == cloudiam.Allow
	}
	techs := cloudiam.DetectPrivesc(can)
	if len(techs) == 0 {
		return
	}
	canFirm := func(a string) bool {
		dec, cond := cloudiam.Authorize(cloudiam.Request{Principal: principal, Action: a, Resource: "*"}, ps)
		return dec == cloudiam.Allow && !cond
	}
	condition := ""
	if len(cloudiam.DetectPrivesc(canFirm)) == 0 {
		condition = "iam-condition-gated escalation (config-possible; validate live)"
	}
	names := make([]string, 0, len(techs))
	for _, t := range techs {
		names = append(names, t.Name)
	}
	inv.Privescs = append(inv.Privescs, cloudgraph.InvPrivesc{
		Principal: principal, Target: cloudgraph.AdminID,
		Detail: strings.Join(names, ", "), Condition: condition,
	})
}

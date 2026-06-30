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
)

// RawAWS mirrors the SUBSET of AWS list-/describe- output the mapper reads. Pure data (no SDK types) so
// Build is unit-testable with fixtures and the SDK stays behind Fetcher.
type RawAWS struct {
	AccountID string
	Users     []RawIAMUser
	Roles     []RawIAMRole
	SGs       []RawSecurityGroup
	Instances []RawInstance
	Buckets   []RawBucket
}

// RawIAMUser / RawIAMRole carry the identity + a fetcher-resolved Admin flag (an attached/inline policy
// grants admin-equivalent — AdministratorAccess or *:*). The role also carries its verbatim trust policy.
type RawIAMUser struct {
	ARN   string
	Name  string
	Admin bool
}
type RawIAMRole struct {
	ARN             string
	Name            string
	Admin           bool
	TrustPolicyJSON string
}

// RawSecurityGroup carries the normalized ingress rules (a JSON array of cloudgraph.SGRule) for one SG.
type RawSecurityGroup struct {
	ID          string
	IngressJSON string
}

// RawInstance is a compute resource; PublicIP + SGIDs + ServicePort drive the grounded reachability eval.
type RawInstance struct {
	ID           string
	Region       string
	PublicIP     bool
	SGIDs        []string
	ServicePort  int    // primary listening port; 0 = unknown → never asserts an internet edge
	ServiceProto string // "tcp" (default) | "udp"
}

// RawBucket is an object store; Public + Sensitive are fetcher-resolved (public-access-block / tags).
type RawBucket struct {
	ARN       string
	Name      string
	Region    string
	Public    bool
	Sensitive bool
}

// Build maps the raw AWS subset into a cloudgraph.Inventory. Pure + grounded (§10).
func Build(raw RawAWS) cloudgraph.Inventory {
	inv := cloudgraph.Inventory{AccountID: raw.AccountID, Provider: "aws"}

	for _, u := range raw.Users {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: u.ARN, Kind: cloudgraph.KindPrincipal, Type: "iam_user", Name: u.Name, Privileged: u.Admin,
		})
	}
	for _, r := range raw.Roles {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: r.ARN, Kind: cloudgraph.KindPrincipal, Type: "iam_role", Name: r.Name, Privileged: r.Admin,
		})
		for _, p := range trustPrincipals(r.TrustPolicyJSON) {
			inv.Trusts = append(inv.Trusts, cloudgraph.InvTrust{Principal: p, Role: r.ARN})
		}
	}

	sgByID := make(map[string]RawSecurityGroup, len(raw.SGs))
	for _, sg := range raw.SGs {
		sgByID[sg.ID] = sg
	}
	for _, in := range raw.Instances {
		inv.Resources = append(inv.Resources, cloudgraph.InvResource{
			ID: in.ID, Kind: cloudgraph.KindResource, Type: "ec2_instance", Region: in.Region, Public: in.PublicIP,
		})
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

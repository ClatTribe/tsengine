package cloudquery

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The prowler check catalog — the EXTERNAL definition of "what is bad", the cloud
// analogue of nuclei templates. Each Check is a real prowler check id plus a
// detector that reads the CloudQuery rows and returns the resources that TRIP it.
// This is what makes the dataset independent: badness is computed from the config
// by prowler's own rules, not hand-asserted by us. The same catalog both (a)
// drives scenario emulation (we plant config that trips chosen checks) and (b)
// produces the findings (EvalProwler), exactly like a real prowler run would.
//
// A check is config-bad ONLY — it says nothing about exploitability. Deciding
// which findings are real attack paths vs inert is the engineer's job (the
// dual-view value, ADR 0002); prowler over-reports by design.

// Check is one catalog entry.
type Check struct {
	ID       string
	Service  string
	Severity types.Severity
	Title    string
	CIS      []string
	// detect returns the resource ids (ARNs) in the dataset that fail this check.
	detect func(t *Tables) []string
}

// Catalog is the supported prowler checks. Extend by appending — every entry is a
// real prowler check id.
var Catalog = []Check{
	{
		ID: "s3_bucket_public_access", Service: "s3", Severity: types.SeverityHigh,
		Title: "S3 bucket allows public access", CIS: []string{"1.20"},
		detect: func(t *Tables) []string {
			var out []string
			for _, b := range t.S3Buckets {
				if b.PolicyAllowsPublic || (!b.BlockPublicACLs && !b.BlockPublicPolicy) {
					out = append(out, b.ARN)
				}
			}
			return out
		},
	},
	{
		ID: "s3_bucket_no_mfa_delete", Service: "s3", Severity: types.SeverityMedium,
		Title: "S3 bucket does not have MFA Delete enabled", CIS: []string{"2.1.3"},
		detect: func(t *Tables) []string {
			var out []string
			for _, b := range t.S3Buckets {
				if !b.MFADelete {
					out = append(out, b.ARN)
				}
			}
			return out
		},
	},
	{
		ID: "ec2_securitygroup_allow_ingress_from_internet_to_any_port", Service: "ec2",
		Severity: types.SeverityHigh, Title: "Security group allows ingress from 0.0.0.0/0", CIS: []string{"5.2"},
		detect: func(t *Tables) []string {
			var out []string
			for _, sg := range t.SecurityGroups {
				if sg.OpenIngressFromInternet {
					out = append(out, sg.ID)
				}
			}
			return out
		},
	},
	{
		ID: "ec2_instance_public_ip", Service: "ec2", Severity: types.SeverityMedium,
		Title: "EC2 instance has a public IP", CIS: nil,
		detect: func(t *Tables) []string {
			var out []string
			for _, e := range t.EC2Instances {
				if e.PublicIPAddress != "" {
					out = append(out, e.ARN)
				}
			}
			return out
		},
	},
	{
		ID: "iam_policy_allows_privilege_escalation", Service: "iam", Severity: types.SeverityCritical,
		Title: "IAM identity policy permits privilege escalation", CIS: []string{"1.16"},
		// prowler-style: evaluates the role's ATTACHED policies only — it does NOT
		// account for a permission boundary. That over-report is exactly what the
		// engineer must triage (a boundary-blocked escalation is config-bad, inert).
		detect: func(t *Tables) []string {
			var out []string
			flag := func(arn string, pols []json.RawMessage) {
				attached := parseDocs(pols)
				can := func(a string) bool { return cloudiam.CanDo(a, attached...) }
				if len(cloudiam.DetectPrivesc(can)) > 0 {
					out = append(out, arn)
				}
			}
			for _, r := range t.IAMRoles {
				flag(r.ARN, r.InlinePolicies)
			}
			for _, u := range t.IAMUsers {
				flag(u.ARN, u.InlinePolicies)
			}
			return out
		},
	},
	{
		ID: "iam_role_trust_policy_allows_wildcard_principal", Service: "iam", Severity: types.SeverityHigh,
		Title: "IAM role trust policy allows a wildcard principal", CIS: nil,
		detect: func(t *Tables) []string {
			var out []string
			for _, r := range t.IAMRoles {
				trust := parseDoc(r.AssumeRolePolicyDocument)
				if trust == nil {
					continue
				}
				// any principal can assume it ⇒ wildcard trust.
				if ok, _ := cloudiam.Allows("sts:AssumeRole", "arn:aws:iam::000000000000:role/anyone", trust); ok {
					out = append(out, r.ARN)
				}
			}
			return out
		},
	},
}

// EvalProwler runs the catalog over a CloudQuery dataset and returns the findings
// — the deterministic, config-grounded "tools say" lens. Findings are stable
// (id = "<check>::<resource>") and sorted, so re-running is byte-identical.
func EvalProwler(t *Tables) []types.Finding {
	var out []types.Finding
	for _, c := range Catalog {
		for _, arn := range c.detect(t) {
			out = append(out, types.Finding{
				ID:       fmt.Sprintf("%s::%s", c.ID, arn),
				RuleID:   "prowler::" + c.ID,
				Tool:     "prowler",
				Severity: c.Severity,
				Title:    c.Title,
				// Endpoint "<service> <resource> @region": resourceOf() joins on field[1].
				Endpoint: fmt.Sprintf("%s %s @account", c.Service, arn),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// FindingID is the canonical id EvalProwler assigns, so an answer key can
// reference findings without depending on the dataset's iteration order.
func FindingID(checkID, arn string) string { return fmt.Sprintf("%s::%s", checkID, arn) }

func parseDoc(raw []byte) *cloudiam.Document {
	if len(raw) == 0 {
		return nil
	}
	d, err := cloudiam.Parse(raw)
	if err != nil {
		return nil
	}
	return d
}

func parseDocs(raws []json.RawMessage) []*cloudiam.Document {
	out := make([]*cloudiam.Document, 0, len(raws))
	for _, r := range raws {
		if d := parseDoc(r); d != nil {
			out = append(out, d)
		}
	}
	return out
}

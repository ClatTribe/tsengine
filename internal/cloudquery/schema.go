// Package cloudquery models a faithful SUBSET of CloudQuery's AWS schema and the
// adapter that turns a CloudQuery sync into the AI Cloud Security Engineer's
// inventory graph (ADR 0002 — "CloudQuery is the eyes, the engine is the brain").
//
// Two jobs live here, and the split is the whole point of the overfitting fix
// (docs/design/cloud-engine-overfitting.md):
//
//  1. The CloudQuery rows carry the RAW config the way a real sync surfaces it —
//     including role TRUST POLICIES and PERMISSION BOUNDARIES, dimensions the
//     cloudgraph.Inventory vocabulary drops.
//  2. ToInventory() is the INGEST SOURCE: it resolves effective permissions
//     (cloudiam over attached ∧ boundary, and trust-policy gating on assume) and
//     emits an already-resolved inventory. Computing effective perms is the
//     source's job, not the engine's (see internal/cloudgraph/ingest.go) — so
//     doing it correctly HERE is what closes the held-out gap.
//
// This is a compact subset (S3, IAM roles, EC2, security groups) — enough to
// exercise public-exposure, instance-profile, assume-role, has-access, and
// privilege-escalation reasoning end to end. Policy documents are stored as the
// JSON-document column type CloudQuery uses.
package cloudquery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Tables is the subset of CloudQuery AWS tables we ingest. Each field is one
// CloudQuery table (named exactly as CloudQuery names it).
type Tables struct {
	S3Buckets      []S3Bucket      `json:"aws_s3_buckets"`
	IAMRoles       []IAMRole       `json:"aws_iam_roles"`
	EC2Instances   []EC2Instance   `json:"aws_ec2_instances"`
	SecurityGroups []SecurityGroup `json:"aws_ec2_security_groups"`
}

// S3Bucket mirrors aws_s3_buckets (subset). Classification rides in tags the way
// real accounts mark data sensitivity (e.g. {"classification":"pii"}).
type S3Bucket struct {
	ARN                string            `json:"arn"`
	Name               string            `json:"name"`
	Region             string            `json:"region"`
	BlockPublicACLs    bool              `json:"block_public_acls"`
	BlockPublicPolicy  bool              `json:"block_public_policy"`
	PolicyAllowsPublic bool              `json:"policy_allows_public"` // bucket policy grants a public principal
	MFADelete          bool              `json:"mfa_delete"`
	Tags               map[string]string `json:"tags,omitempty"`
}

// IAMRole mirrors aws_iam_roles (subset). The policy columns are JSON documents,
// exactly as CloudQuery stores them.
type IAMRole struct {
	ARN                      string            `json:"arn"`
	Name                     string            `json:"name"`
	AssumeRolePolicyDocument json.RawMessage   `json:"assume_role_policy_document"`       // the TRUST policy
	InlinePolicies           []json.RawMessage `json:"inline_policy_documents,omitempty"` // attached/inline identity policies
	PermissionsBoundary      json.RawMessage   `json:"permissions_boundary_document,omitempty"`
	Tags                     map[string]string `json:"tags,omitempty"`
}

// EC2Instance mirrors aws_ec2_instances (subset).
type EC2Instance struct {
	ARN                       string   `json:"arn"`
	Name                      string   `json:"name"`
	PublicIPAddress           string   `json:"public_ip_address"`             // "" if none
	IAMInstanceProfileRoleARN string   `json:"iam_instance_profile_role_arn"` // the role it runs as
	SecurityGroupIDs          []string `json:"security_group_ids"`
}

// SecurityGroup mirrors aws_ec2_security_groups (subset). OpenIngressFromInternet
// is true when any ingress rule allows 0.0.0.0/0.
type SecurityGroup struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	OpenIngressFromInternet bool   `json:"open_ingress_from_internet"`
}

// Save writes each table to <dir>/<table>.json — the shape a CloudQuery sync to
// the JSON destination produces (one file per table).
func (t *Tables) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	files := map[string]any{
		"aws_s3_buckets.json":          t.S3Buckets,
		"aws_iam_roles.json":           t.IAMRoles,
		"aws_ec2_instances.json":       t.EC2Instances,
		"aws_ec2_security_groups.json": t.SecurityGroups,
	}
	for name, rows := range files {
		b, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return fmt.Errorf("cloudquery: write %s: %w", name, err)
		}
	}
	return nil
}

// Load reads a CloudQuery dataset directory (one JSON file per table).
func Load(dir string) (*Tables, error) {
	var t Tables
	for name, dst := range map[string]any{
		"aws_s3_buckets.json":          &t.S3Buckets,
		"aws_iam_roles.json":           &t.IAMRoles,
		"aws_ec2_instances.json":       &t.EC2Instances,
		"aws_ec2_security_groups.json": &t.SecurityGroups,
	} {
		b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // operator-provided dataset dir
		if err != nil {
			if os.IsNotExist(err) {
				continue // a sync may omit empty tables
			}
			return nil, fmt.Errorf("cloudquery: read %s: %w", name, err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			return nil, fmt.Errorf("cloudquery: parse %s: %w", name, err)
		}
	}
	return &t, nil
}

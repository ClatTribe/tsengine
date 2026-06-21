package connector

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// AWS onboards a customer's AWS account for cloud_account posture scanning (prowler — the
// engine's cloud_account asset). AWS has no OAuth consent flow; the industry-standard
// partner onboarding is a CloudFormation "launch stack" that provisions a cross-account,
// READ-ONLY IAM role (SecurityAudit + ViewOnlyAccess) trusting tsengine's account with a
// per-tenant External ID. So this connector adapts the OAuth-shaped interface:
//
//   - OAuthURL returns the CloudFormation quick-create-stack URL (the "launch stack" link
//     the user clicks); the CSRF state doubles as the role's External ID (tenant binding).
//   - Exchange takes the role ARN the stack outputs (submitted back as `code`), validates
//     it, and records it as the connection's SecretRef — the role ARN IS the credential.
//   - Discover yields the cloud_account asset the engine scans with prowler.
//
// The live scan (STS assume-role → prowler) needs the role to exist + tsengine runtime
// creds — that's the deployment step. The onboarding wiring here is provider-correct and
// unit-tested. Configure via AWS_CFN_TEMPLATE_URL / AWS_TRUST_ACCOUNT_ID / AWS_REGION.
type AWS struct {
	TemplateURL    string // S3 URL of the cross-account-role CloudFormation template
	TrustAccountID string // tsengine's AWS account id (the provisioned role trusts it)
	Region         string // console region for the launch URL
	// Writer is the live, reversible AWS write path (ADR 0009 Phase 5). Nil → no live cloud
	// remediation is configured, so Apply returns an honest "not configured" error (never a
	// false "done"). The real impl assumes the onboarded cross-account role and signs the call
	// (SigV4) — that needs runtime write creds + the AWS SDK, the deployment step. Injectable
	// so the write path is unit-tested against a fake without live creds (the Okta pattern).
	Writer AWSWriter
}

// AWSWriter performs the reversible cloud mutations tsengine remediates to. Today only S3
// public-access block (the fix for a public-bucket DSPM/CSPM finding).
type AWSWriter interface {
	// BlockS3PublicAccess enables S3 Block Public Access on the bucket — the reversible
	// remediation for a publicly-exposed bucket (PutPublicAccessBlock, all four flags on).
	BlockS3PublicAccess(ctx context.Context, bucket string) error
}

// NewAWS builds the connector. Region defaults to us-east-1.
func NewAWS(templateURL, trustAccountID, region string) *AWS {
	return &AWS{TemplateURL: templateURL, TrustAccountID: trustAccountID, Region: nz(region, "us-east-1")}
}

func (a *AWS) Kind() string { return platform.ConnAWS }

// OAuthURL returns the CloudFormation quick-create-stack link. state → the role's
// ExternalId (CSRF + tenant binding); the template provisions the read-only role.
func (a *AWS) OAuthURL(state, _ string) string {
	q := url.Values{
		"templateURL":            {a.TemplateURL},
		"stackName":              {"tsengine-readonly"},
		"param_ExternalId":       {state},
		"param_TrustedAccountId": {a.TrustAccountID},
	}
	return fmt.Sprintf("https://%s.console.aws.amazon.com/cloudformation/home?region=%s#/stacks/quickcreate?%s",
		a.Region, a.Region, q.Encode())
}

// Exchange records the cross-account role ARN the stack produced. `code` is that ARN (the
// callback carries it, not an OAuth code) — the role ARN is the credential.
func (a *AWS) Exchange(_ context.Context, code, _ string) (platform.Connection, error) {
	arn := strings.TrimSpace(code)
	acct, err := accountIDFromRoleARN(arn)
	if err != nil {
		return platform.Connection{}, err
	}
	return platform.Connection{
		Kind: platform.ConnAWS, Status: platform.ConnActive,
		Account: acct, SecretRef: arn, CreatedAt: time.Now().UTC(),
	}, nil
}

// Discover yields the cloud_account asset the engine scans (prowler over the assumed role).
func (a *AWS) Discover(_ context.Context, c platform.Connection, _ string) ([]platform.Asset, error) {
	return []platform.Asset{{
		TenantID: c.TenantID, ConnectionID: c.ID,
		Type:         "cloud_account",
		Target:       nz(c.Account, "aws"),
		Meta:         map[string]string{"provider": "aws", "role_arn": c.SecretRef},
		DiscoveredAt: time.Now().UTC(),
	}}, nil
}

// Watch is a no-op: cloud posture is scheduled, not webhook-driven.
func (a *AWS) Watch(context.Context, platform.Connection, []byte) ([]Trigger, error) {
	return nil, nil
}

// Apply: cloud remediation has no live write path yet (honest stub, pending write creds).
// Apply executes an approved (HITL-gated) cloud remediation. It routes on the action's
// machine-readable remediation_type + target (set by remediate.proposeCloud). Reached only
// after the desk approves (§18.2 inv. 3); the connector never writes on its own. An unknown
// remediation_type or an unconfigured Writer surfaces as an error — the action stays
// un-applied, never falsely "done".
func (a *AWS) Apply(ctx context.Context, _ platform.Connection, _ string, act platform.Action) error {
	rt, _ := act.Payload["remediation_type"].(string)
	target, _ := act.Payload["target"].(string)
	switch rt {
	case "s3_block_public_access":
		bucket := bucketFromTarget(target)
		if bucket == "" {
			return fmt.Errorf("aws apply: s3_block_public_access action %s has no target bucket", act.ID)
		}
		if a.Writer == nil {
			return fmt.Errorf("aws apply: no live AWS write path configured (needs assume-role write creds); "+
				"action %s (block public access on %s) left un-applied", act.ID, bucket)
		}
		return a.Writer.BlockS3PublicAccess(ctx, bucket)
	case "":
		return fmt.Errorf("aws apply: action %s carries no remediation_type — no live write path, left un-applied", act.ID)
	default:
		return fmt.Errorf("aws apply: remediation_type %q has no live AWS write path yet (target %s)", rt, target)
	}
}

// bucketFromTarget extracts the bucket name from an S3 ARN ("arn:aws:s3:::name/key") or a bare
// name. Object keys / a trailing path are dropped — Block Public Access is bucket-scoped.
func bucketFromTarget(t string) string {
	t = strings.TrimSpace(t)
	t = strings.TrimPrefix(t, "arn:aws:s3:::")
	if i := strings.IndexByte(t, '/'); i >= 0 {
		t = t[:i]
	}
	return t
}

// accountIDFromRoleARN extracts the 12-digit account id from an IAM role ARN
// (arn:aws:iam::<account>:role/<name>).
func accountIDFromRoleARN(arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" || parts[2] != "iam" || !strings.HasPrefix(parts[5], "role/") {
		return "", fmt.Errorf("aws: not a valid IAM role ARN: %q", arn)
	}
	acct := parts[4]
	if len(acct) != 12 || !isDigits(acct) {
		return "", fmt.Errorf("aws: role ARN has a malformed account id: %q", acct)
	}
	return acct, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

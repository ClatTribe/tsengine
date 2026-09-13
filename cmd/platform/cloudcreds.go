package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// cloudcreds.go decides WHOSE credentials a cloud_account scan runs with.
//
// The defect this closes: the sandbox dispatcher forwarded the platform's OWN environment
// (`AWS_ACCESS_KEY_ID`…) into every cloud scan, so prowler and scoutsuite on a tenant's connected
// account ran as the OPERATOR — against whatever account those variables happened to reach, or no
// account at all — while the connection's role ARN sat unread in the asset's Meta. Meanwhile the live
// inventory read (`awsfetch`) and the policy simulator already assumed that role correctly. So one
// half of "connect your account" was tenant-scoped and the other half was not, and the posture
// findings the second half produced carried the tenant's id on somebody else's account.
//
// The rule: an asset that carries a connection role is scanned AS THAT ROLE, through the same
// assume-role path the inventory read uses (same region defaulting, same external-id guard — the
// tenant id issued on the connect link), and if the role cannot be assumed the scan FAILS. It does
// not fall back to the operator's environment, because a scan that quietly runs as a different
// principal is the exact defect being closed. An asset with no role (a deliberately
// operator-credentialed account, or a GCP/Azure asset whose credential travels differently) keeps
// today's behaviour.

// roleAssumer returns temporary credentials for a role, or an error. The seam exists so the decision
// above can be tested without STS.
type roleAssumer func(ctx context.Context, region, roleARN, externalID string) (aws.Credentials, error)

// stsAssume is the production assumer: awsfetch's assume-role config, resolved once.
func stsAssume(ctx context.Context, region, roleARN, externalID string) (aws.Credentials, error) {
	cfg, err := awsfetch.AssumeRoleConfig(ctx, region, roleARN, externalID)
	if err != nil {
		return aws.Credentials{}, err
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("assume %s: %w", roleARN, err)
	}
	return creds, nil
}

// cloudScanEnv returns the environment a cloud_account scan runs with.
func cloudScanEnv(ctx context.Context, a platform.Asset, assume roleAssumer) ([]string, error) {
	roleARN := a.Meta["role_arn"]
	if roleARN == "" {
		return cloudCredentialEnv(), nil
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	creds, err := assume(ctx, region, roleARN, a.TenantID)
	if err != nil {
		// Loud, not a fallback. The runner records a failed scan (ToolsFailed / degraded pass), which
		// is the honest state; a scan as the operator would be a clean-looking result about the
		// wrong account.
		return nil, fmt.Errorf("cloud scan: cannot assume the connected role for tenant %s: %w", a.TenantID, err)
	}
	env := []string{
		"AWS_ACCESS_KEY_ID=" + creds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + creds.SecretAccessKey,
		"AWS_REGION=" + region,
		"AWS_DEFAULT_REGION=" + region,
	}
	if creds.SessionToken != "" {
		env = append(env, "AWS_SESSION_TOKEN="+creds.SessionToken)
	}
	return env, nil
}

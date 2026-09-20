package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A connected account is scanned AS ITS ROLE. Before this, the dispatcher forwarded the operator's
// own AWS_* environment into the sandbox and the asset's role_arn was never read — so prowler on a
// tenant's account ran as whoever the platform host happened to be. These pin the decision, with the
// operator env deliberately set so a regression is visible as operator credentials in the output.
func TestCloudScanEnv_ConnectedAccountRunsAsItsRoleNeverTheOperator(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAOPERATOR")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "operator-secret")
	t.Setenv("AWS_REGION", "eu-west-1")

	var got struct{ region, role, ext string }
	assume := func(_ context.Context, region, roleARN, externalID string) (aws.Credentials, error) {
		got.region, got.role, got.ext = region, roleARN, externalID
		return aws.Credentials{AccessKeyID: "ASIATENANT", SecretAccessKey: "tenant-secret", SessionToken: "tok"}, nil
	}
	a := platform.Asset{TenantID: "ten-1", Type: "cloud_account", Target: "aws",
		Meta: map[string]string{"provider": "aws", "role_arn": "arn:aws:iam::123456789012:role/TensorShieldReadOnly"}}

	env, err := cloudScanEnv(context.Background(), a, assume)
	if err != nil {
		t.Fatal(err)
	}
	if got.role != a.Meta["role_arn"] || got.ext != "ten-1" || got.region != "eu-west-1" {
		t.Errorf("assumed (%q, ext %q, region %q); want the connection's role with the tenant id as external id", got.role, got.ext, got.region)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{"AWS_ACCESS_KEY_ID=ASIATENANT", "AWS_SECRET_ACCESS_KEY=tenant-secret", "AWS_SESSION_TOKEN=tok", "AWS_REGION=eu-west-1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("env lacks %s:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "AKIAOPERATOR") || strings.Contains(joined, "operator-secret") {
		t.Errorf("the OPERATOR's credentials reached a tenant's scan:\n%s", joined)
	}
}

// A role that cannot be assumed FAILS the scan. Falling back to the operator's environment would be
// the defect this file exists to close: a clean-looking result about the wrong account.
func TestCloudScanEnv_UnassumableRoleFailsRatherThanFallingBack(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAOPERATOR")
	assume := func(context.Context, string, string, string) (aws.Credentials, error) {
		return aws.Credentials{}, errors.New("AccessDenied: external id mismatch")
	}
	a := platform.Asset{TenantID: "ten-1", Type: "cloud_account", Meta: map[string]string{"role_arn": "arn:aws:iam::1:role/x"}}
	env, err := cloudScanEnv(context.Background(), a, assume)
	if err == nil || !strings.Contains(err.Error(), "ten-1") {
		t.Fatalf("want an error naming the tenant, got env=%v err=%v", env, err)
	}
	if env != nil {
		t.Errorf("a failed assume must yield no environment at all, got %v", env)
	}
}

// An asset with no connection role keeps the operator path — a deliberately operator-credentialed
// account, or a GCP/Azure asset whose credential travels by another variable.
func TestCloudScanEnv_NoRoleKeepsTheOperatorEnvironment(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAOPERATOR")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/run/gcp.json")
	called := false
	assume := func(context.Context, string, string, string) (aws.Credentials, error) {
		called = true
		return aws.Credentials{}, nil
	}
	env, err := cloudScanEnv(context.Background(), platform.Asset{TenantID: "ten-1", Type: "cloud_account", Meta: map[string]string{"provider": "gcp", "project_id": "p"}}, assume)
	if err != nil || called {
		t.Fatalf("no role must not assume anything: err=%v called=%v", err, called)
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "AKIAOPERATOR") || !strings.Contains(joined, "GOOGLE_APPLICATION_CREDENTIALS=/run/gcp.json") {
		t.Errorf("operator environment not forwarded for a role-less asset: %s", joined)
	}
}

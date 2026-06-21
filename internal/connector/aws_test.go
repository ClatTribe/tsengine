package connector

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestAWS_OAuthURL_IsLaunchStack(t *testing.T) {
	a := NewAWS("https://s3.amazonaws.com/tsengine/role.yaml", "999988887777", "us-west-2")
	u := a.OAuthURL("tenant-abc", "")
	for _, want := range []string{
		"us-west-2.console.aws.amazon.com/cloudformation/home",
		"quickcreate",
		"param_ExternalId=tenant-abc", // CSRF state → role External ID
		"param_TrustedAccountId=999988887777",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("launch URL missing %q:\n%s", want, u)
		}
	}
}

func TestAWS_Exchange_CapturesRoleARN(t *testing.T) {
	a := NewAWS("t", "111122223333", "")
	c, err := a.Exchange(context.Background(), "  arn:aws:iam::123456789012:role/tsengine-readonly  ", "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if c.Kind != platform.ConnAWS || c.Status != platform.ConnActive {
		t.Errorf("connection: %+v", c)
	}
	if c.Account != "123456789012" {
		t.Errorf("account id: want 123456789012, got %q", c.Account)
	}
	if c.SecretRef != "arn:aws:iam::123456789012:role/tsengine-readonly" {
		t.Errorf("SecretRef should be the role ARN, got %q", c.SecretRef)
	}
}

func TestAWS_Exchange_RejectsBadARN(t *testing.T) {
	a := NewAWS("t", "1", "")
	for _, bad := range []string{
		"", "not-an-arn",
		"arn:aws:s3:::bucket",              // not iam
		"arn:aws:iam::123:role/x",          // short account id
		"arn:aws:iam::123456789012:user/x", // not a role
	} {
		if _, err := a.Exchange(context.Background(), bad, ""); err == nil {
			t.Errorf("expected rejection for %q", bad)
		}
	}
}

func TestAWS_Discover_YieldsCloudAccountAsset(t *testing.T) {
	a := NewAWS("t", "1", "")
	assets, err := a.Discover(context.Background(),
		platform.Connection{ID: "c1", TenantID: "t1", Account: "123456789012", SecretRef: "arn:aws:iam::123456789012:role/r"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].Type != "cloud_account" || assets[0].Target != "123456789012" {
		t.Fatalf("want one cloud_account asset for the account, got %+v", assets)
	}
	if assets[0].Meta["provider"] != "aws" {
		t.Errorf("asset meta should mark provider=aws, got %v", assets[0].Meta)
	}
}

// fakeS3Writer records BlockS3PublicAccess calls (ADR 0009 Phase 5 — the injectable write
// path, tested without live AWS creds, mirroring the Okta fake-org pattern).
type fakeS3Writer struct {
	blocked []string
	err     error
}

func (f *fakeS3Writer) BlockS3PublicAccess(_ context.Context, bucket string) error {
	if f.err != nil {
		return f.err
	}
	f.blocked = append(f.blocked, bucket)
	return nil
}

func TestAWS_Apply_S3BlockPublicAccess(t *testing.T) {
	w := &fakeS3Writer{}
	a := NewAWS("", "", "")
	a.Writer = w
	act := platform.Action{ID: "act-1", Payload: map[string]any{
		"remediation_type": "s3_block_public_access",
		"target":           "arn:aws:s3:::cust-pii/some/key",
	}}
	if err := a.Apply(context.Background(), platform.Connection{}, "tok", act); err != nil {
		t.Fatalf("approved s3 block should apply: %v", err)
	}
	// The ARN (with an object key) is reduced to the bucket name.
	if len(w.blocked) != 1 || w.blocked[0] != "cust-pii" {
		t.Errorf("expected BlockS3PublicAccess(\"cust-pii\"), got %v", w.blocked)
	}
}

func TestAWS_Apply_HonestErrors(t *testing.T) {
	a := NewAWS("", "", "")
	// No Writer configured → honest "not configured" error (never falsely done).
	act := platform.Action{ID: "a", Payload: map[string]any{"remediation_type": "s3_block_public_access", "target": "b"}}
	if err := a.Apply(context.Background(), platform.Connection{}, "", act); err == nil || !strings.Contains(err.Error(), "no live AWS write path") {
		t.Errorf("nil Writer must error honestly, got %v", err)
	}
	// Unknown remediation_type → error, not a silent success.
	a.Writer = &fakeS3Writer{}
	unknown := platform.Action{ID: "a", Payload: map[string]any{"remediation_type": "delete_everything", "target": "b"}}
	if err := a.Apply(context.Background(), platform.Connection{}, "", unknown); err == nil {
		t.Error("unknown remediation_type must error")
	}
	// No remediation_type at all → error (the account-scoped runbook has no live write path).
	none := platform.Action{ID: "a", Payload: map[string]any{"target": "b"}}
	if err := a.Apply(context.Background(), platform.Connection{}, "", none); err == nil {
		t.Error("missing remediation_type must error")
	}
}

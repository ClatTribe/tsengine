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

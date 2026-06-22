package connector

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// GCP onboards a customer's Google Cloud project for cloud_account posture scanning (prowler — the
// engine's cloud_account asset, which supports GCP). Like AWS, GCP has no OAuth consent flow that
// fits server-to-server posture scanning; the standard partner onboarding is read-only delegation:
// the customer grants tsengine's service account the Security Reviewer role on their project. So
// this connector adapts the OAuth-shaped interface the same way connector.AWS does:
//
//   - OAuthURL returns the GCP console IAM page for the customer to grant tsengine's service
//     account read-only access; the CSRF state doubles as the tenant binding.
//   - Exchange takes the GCP project ID the user submits back (as `code`), validates it, and
//     records it as the connection's SecretRef/Account — the project (+ the granted SA) is the
//     credential reference.
//   - Discover yields the cloud_account asset the engine scans with prowler (--provider gcp).
//
// The live scan (impersonate the granted SA → prowler gcp) needs the role grant + tsengine runtime
// creds — the deployment step. The onboarding wiring here is provider-correct and unit-tested.
// Configure via GCP_TRUST_SERVICE_ACCOUNT (tsengine's SA the customer grants access to).
type GCP struct {
	TrustServiceAccount string // tsengine's SA email the customer grants Security Reviewer to
	ConsoleBase         string // default https://console.cloud.google.com
}

// NewGCP builds the connector.
func NewGCP(trustServiceAccount string) *GCP {
	return &GCP{TrustServiceAccount: trustServiceAccount, ConsoleBase: "https://console.cloud.google.com"}
}

func (g *GCP) Kind() string { return platform.ConnGCP }

func (g *GCP) consoleBase() string {
	if g.ConsoleBase == "" {
		return "https://console.cloud.google.com"
	}
	return strings.TrimRight(g.ConsoleBase, "/")
}

// OAuthURL returns the GCP IAM-admin console link where the customer grants tsengine's service
// account read-only access. state → the CSRF/tenant binding; the customer adds TrustServiceAccount
// with the Security Reviewer role, then submits their project ID back (Exchange).
func (g *GCP) OAuthURL(state, _ string) string {
	q := url.Values{
		"state":      {state},
		"grant_to":   {g.TrustServiceAccount}, // the SA the customer should grant Security Reviewer
		"grant_role": {"roles/iam.securityReviewer"},
	}
	return g.consoleBase() + "/iam-admin/iam?" + q.Encode()
}

// Exchange records the GCP project the customer onboarded. `code` is the project ID (the callback
// carries it, not an OAuth code) — the project (+ the granted SA) is the credential reference.
func (g *GCP) Exchange(_ context.Context, code, _ string) (platform.Connection, error) {
	project := strings.TrimSpace(code)
	if err := validateGCPProjectID(project); err != nil {
		return platform.Connection{}, err
	}
	return platform.Connection{
		Kind: platform.ConnGCP, Status: platform.ConnActive,
		Account: project, SecretRef: project, CreatedAt: time.Now().UTC(),
	}, nil
}

// Discover yields the cloud_account asset the engine scans (prowler --provider gcp over the
// project, impersonating the granted SA).
func (g *GCP) Discover(_ context.Context, c platform.Connection, _ string) ([]platform.Asset, error) {
	return []platform.Asset{{
		TenantID: c.TenantID, ConnectionID: c.ID,
		Type:         "cloud_account",
		Target:       nz(c.Account, "gcp"),
		Meta:         map[string]string{"provider": "gcp", "project_id": c.Account},
		DiscoveredAt: time.Now().UTC(),
	}}, nil
}

// Watch is a no-op: cloud posture is scheduled, not webhook-driven.
func (g *GCP) Watch(context.Context, platform.Connection, []byte) ([]Trigger, error) {
	return nil, nil
}

// Apply: GCP remediation has no live write path yet (honest stub, pending write creds) — an action
// is never falsely reported "done".
func (g *GCP) Apply(_ context.Context, _ platform.Connection, _ string, act platform.Action) error {
	rt, _ := act.Payload["remediation_type"].(string)
	if rt == "" {
		return fmt.Errorf("gcp apply: action %s carries no remediation_type — no live write path, left un-applied", act.ID)
	}
	return fmt.Errorf("gcp apply: remediation_type %q has no live GCP write path yet (needs impersonation write creds)", rt)
}

// validateGCPProjectID checks the GCP project-ID rules: 6–30 chars, lowercase letters/digits/
// hyphens, starts with a letter, doesn't end with a hyphen. Grounded — we never record a malformed
// project (which would silently fail every scan).
func validateGCPProjectID(p string) error {
	if len(p) < 6 || len(p) > 30 {
		return fmt.Errorf("gcp: project id %q must be 6–30 characters", p)
	}
	if p[0] < 'a' || p[0] > 'z' {
		return fmt.Errorf("gcp: project id %q must start with a lowercase letter", p)
	}
	if p[len(p)-1] == '-' {
		return fmt.Errorf("gcp: project id %q must not end with a hyphen", p)
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
			return fmt.Errorf("gcp: project id %q has an invalid character %q", p, string(r))
		}
	}
	return nil
}

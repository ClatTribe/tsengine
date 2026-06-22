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
	// Writer is the operator-default live write path (wired from operator env). Nil → no operator
	// default. The real impl (gcpremediate.GCSWriter) impersonates a write SA + calls the storage
	// SDK; injectable so the write path is unit-tested against a fake without live creds.
	Writer GCPWriter
	// WriterForConfig builds a PER-TENANT write path from the customer's own write SA
	// (Connection.Config[remediation_impersonate_sa]). Injected in cmd/platform
	// (gcpremediate.NewGCSWriter) so package connector stays SDK-free. Nil → only the operator default.
	WriterForConfig func(impersonateSA string) GCPWriter
}

// writerFor picks the per-tenant write path when the connection carries an enabled remediation
// config (the customer's own impersonation SA); else falls back to the operator-default Writer.
func (g *GCP) writerFor(conn platform.Connection) GCPWriter {
	if g.WriterForConfig != nil && conn.Config[platform.CfgRemediationEnabled] == "true" {
		if sa := conn.Config[platform.CfgRemediationSA]; sa != "" {
			return g.WriterForConfig(sa)
		}
	}
	return g.Writer
}

// GCPWriter performs the reversible GCP mutations tsengine remediates to. Today only GCS Public
// Access Prevention (the fix for a publicly-exposed bucket).
type GCPWriter interface {
	// EnforceBucketPublicAccessPrevention sets the bucket's Public Access Prevention to "enforced"
	// (the GCS equivalent of S3 Block Public Access). project scopes the credentials/impersonation.
	EnforceBucketPublicAccessPrevention(ctx context.Context, project, bucket string) error
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

// Apply executes an approved (HITL-gated) GCP remediation, routing on the action's machine-readable
// remediation_type. Reached only after the desk approves (§18.2 inv. 3); the connector never writes
// on its own. An unknown type or an unconfigured Writer surfaces as an error — the action stays
// un-applied, never falsely "done".
func (g *GCP) Apply(ctx context.Context, c platform.Connection, _ string, act platform.Action) error {
	rt, _ := act.Payload["remediation_type"].(string)
	switch rt {
	case "gcs_public_access_prevention":
		bucket := gcsBucketFromTarget(strFrom(act.Payload, "target"))
		if bucket == "" {
			return fmt.Errorf("gcp apply: %s action %s has no target bucket", rt, act.ID)
		}
		writer := g.writerFor(c)
		if writer == nil {
			return fmt.Errorf("gcp apply: no live GCP write path configured (set this connection's remediation "+
				"SA, or the operator default); action %s (enforce public-access-prevention on %s) left un-applied", act.ID, bucket)
		}
		return writer.EnforceBucketPublicAccessPrevention(ctx, c.Account, bucket)
	case "":
		return fmt.Errorf("gcp apply: action %s carries no remediation_type — no live write path, left un-applied", act.ID)
	default:
		return fmt.Errorf("gcp apply: remediation_type %q has no live GCP write path yet (target %s)", rt, strFrom(act.Payload, "target"))
	}
}

// gcsBucketFromTarget extracts the GCS bucket name from a finding target — a "gs://bucket/obj" URL,
// a bare "bucket", or a "bucket/path". Object keys / trailing path are dropped (PAP is bucket-scoped).
func gcsBucketFromTarget(t string) string {
	t = strings.TrimSpace(t)
	t = strings.TrimPrefix(t, "gs://")
	t = strings.TrimPrefix(t, "https://storage.googleapis.com/")
	if i := strings.IndexByte(t, '/'); i >= 0 {
		t = t[:i]
	}
	return t
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

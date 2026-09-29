package cloudprobe

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
	pt "google.golang.org/api/policytroubleshooter/v1"
)

// gcp.go is the LIVE GCP adapter for the provider dry-run — the GCP rung of the same verification
// ladder aws.go reaches on AWS (ADR 0029 D2b).
//
// # WHY POLICY TROUBLESHOOTER, NOT testIamPermissions
//
// The obvious-looking GCP call — resourcemanager.Projects.TestIamPermissions — answers a DIFFERENT
// question: "which of these permissions does the AUTHENTICATED CALLER hold?" Our tuple is about an
// ARBITRARY principal (the identity on an attack-path edge), not about us. Answering with
// testIamPermissions would confidently report OUR service account's access as if it were the
// principal's — a §10 category error that arrives wearing a provider's authority. So this uses the
// IAM Policy Troubleshooter (troubleshootIamPolicy), which takes a full (principal, resource,
// permission) tuple and returns Google's own access decision for THAT principal. It is read-only by
// construction — it evaluates policy and performs nothing.
//
// # THE THREE-VALUED MAPPING, CONSERVATIVE IN ONE DIRECTION ONLY
//
//   - GRANTED       → allowed, decided.
//   - NOT_GRANTED   → denied, DECIDED — a real refusal (no policy grants it), the GCP twin of AWS's
//     implicit deny. It is evidence, not an absence of one, so it is Known.
//   - UNKNOWN_CONDITIONAL → the principal has it only if a condition evaluates true. That is a maybe
//     about the real world, not a decision, so it is UNKNOWN with the reason stated (the AWS
//     missing-context analog).
//   - UNKNOWN_INFO_DENIED → Troubleshooter itself could not read all the policies it needed. A verdict
//     built on a partial view is not one, so it is UNKNOWN — never read as a deny, which would close a
//     live path on our own lack of visibility.
//   - anything else / unspecified / no access field → UNKNOWN.

// gcpTroubleshootAPI is the one method this adapter needs — an interface so the mapping is tested
// against the real response shape without a GCP project.
type gcpTroubleshootAPI interface {
	Troubleshoot(ctx context.Context, req *pt.GoogleCloudPolicytroubleshooterV1TroubleshootIamPolicyRequest) (*pt.GoogleCloudPolicytroubleshooterV1TroubleshootIamPolicyResponse, error)
}

// GCPSimulator evaluates tuples against a customer project via the Policy Troubleshooter, optionally
// impersonating a scoped read-only service account (the same shape gcpremediate uses for writes,
// except the permission needed here — policytroubleshooter.iam.troubleshoot — is a READ).
type GCPSimulator struct {
	ImpersonateSA string // read-capable SA to impersonate in the customer project; "" → ADC

	newAPI func(ctx context.Context) (gcpTroubleshootAPI, error) // injectable for tests
}

// NewGCPSimulator builds a simulator. impersonateSA is the customer's scoped read-only SA to
// impersonate (empty → Application Default Credentials).
func NewGCPSimulator(impersonateSA string) *GCPSimulator {
	return &GCPSimulator{ImpersonateSA: impersonateSA}
}

func (s *GCPSimulator) api(ctx context.Context) (gcpTroubleshootAPI, error) {
	if s.newAPI != nil {
		return s.newAPI(ctx)
	}
	var opts []option.ClientOption
	if s.ImpersonateSA != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: s.ImpersonateSA,
			Scopes:          []string{"https://www.googleapis.com/auth/cloud-platform"},
		})
		if err != nil {
			return nil, err
		}
		opts = append(opts, option.WithTokenSource(ts))
	}
	svc, err := pt.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &realTroubleshoot{svc: svc}, nil
}

// realTroubleshoot is the live client wrapper — the only code touching network/credentials, replaced
// by a fake in tests.
type realTroubleshoot struct{ svc *pt.Service }

func (r *realTroubleshoot) Troubleshoot(ctx context.Context, req *pt.GoogleCloudPolicytroubleshooterV1TroubleshootIamPolicyRequest) (*pt.GoogleCloudPolicytroubleshooterV1TroubleshootIamPolicyResponse, error) {
	return r.svc.Iam.Troubleshoot(req).Context(ctx).Do()
}

// Simulate asks Google's Policy Troubleshooter whether principal may perform action (a GCP IAM
// permission, e.g. storage.buckets.setIamPolicy) on resource (a full resource name).
func (s *GCPSimulator) Simulate(ctx context.Context, principal, action, resource string) (Decision, error) {
	// A tuple missing any leg is refused rather than sent: Troubleshooter requires all three, and a
	// partial request would either error or answer a different question with provider authority.
	if strings.TrimSpace(principal) == "" || strings.TrimSpace(action) == "" || strings.TrimSpace(resource) == "" {
		return Decision{Known: false, Why: "principal, permission and resource are all required to troubleshoot a GCP tuple"}, nil
	}
	api, err := s.api(ctx)
	if err != nil {
		return Decision{Known: false, Why: "could not reach the project: " + err.Error()}, err
	}
	req := &pt.GoogleCloudPolicytroubleshooterV1TroubleshootIamPolicyRequest{
		AccessTuple: &pt.GoogleCloudPolicytroubleshooterV1AccessTuple{
			Principal:        principal,
			Permission:       action,
			FullResourceName: resource,
		},
	}
	out, err := api.Troubleshoot(ctx, req)
	if err != nil {
		// A call failure is UNKNOWN, never a deny — a throttle, an expired impersonation or a missing
		// troubleshoot permission would otherwise silently close every path it touched.
		return Decision{Known: false, Why: "troubleshoot call failed: " + err.Error()}, err
	}
	return decisionFromGCP(out, action), nil
}

// decisionFromGCP maps the Policy Troubleshooter access state onto our three-valued answer.
func decisionFromGCP(out *pt.GoogleCloudPolicytroubleshooterV1TroubleshootIamPolicyResponse, action string) Decision {
	if out == nil || strings.TrimSpace(out.Access) == "" {
		return Decision{Known: false, Why: "the troubleshooter returned no access decision for " + action}
	}
	switch out.Access {
	case "GRANTED":
		return Decision{Allowed: true, Known: true, Detail: "granted (GCP Policy Troubleshooter)"}
	case "NOT_GRANTED":
		return Decision{Allowed: false, Known: true, Detail: "not granted — no policy grants it (GCP Policy Troubleshooter)"}
	case "UNKNOWN_CONDITIONAL":
		return Decision{Known: false, Why: "granted only if an IAM condition evaluates true, so this describes a maybe rather than a decision"}
	case "UNKNOWN_INFO_DENIED":
		return Decision{Known: false, Why: "Policy Troubleshooter could not read all the policies it needed to decide, so a verdict would rest on a partial view"}
	default:
		return Decision{Known: false, Why: fmt.Sprintf("unrecognised access state %q", out.Access)}
	}
}

// Describe is the coverage line that rides with every GCP probe report — the method and its limits,
// not just the provider's name.
func (s *GCPSimulator) Describe() string {
	where := "Application Default Credentials"
	if s.ImpersonateSA != "" {
		where = "impersonating " + s.ImpersonateSA
	}
	return "GCP IAM Policy Troubleshooter (troubleshootIamPolicy) via " + where + " — evaluates the " +
		"principal's real allow-policies across the resource hierarchy; a condition-gated grant or a " +
		"policy it cannot read arrives as unknown rather than as a decision"
}

var _ Simulator = (*GCPSimulator)(nil)

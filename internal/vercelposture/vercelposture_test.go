package vercelposture

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func at() time.Time { return time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC) }

func opts() Options { return Options{Now: at} }

func b(v bool) *bool { return &v }

func has(fs []types.Finding, rule string) *types.Finding {
	for i := range fs {
		if strings.Contains(fs[i].RuleID, rule) {
			return &fs[i]
		}
	}
	return nil
}

// ── THE BASELINE THAT MAKES THE REST MEAN SOMETHING ──────────────────────────────────────────────

// A well-configured account yields NOTHING. Without this, an assessor that flagged every project
// would pass every detection test below and be useless in production.
func TestWellConfiguredAccount_YieldsNothing(t *testing.T) {
	got := Assess(Snapshot{Projects: []Project{{
		Name: "acme-web", PreviewProtected: b(true), ProductionProtected: b(false), PublicSource: b(true),
		EnvVars: []EnvVar{
			{Key: "DATABASE_URL", Targets: []string{"production"}, Sensitive: true},
			{Key: "NEXT_PUBLIC_FEATURE_X", Targets: []string{"production", "preview"}},
		},
		ProductionDomains: []string{"acme.com"},
	}}}, opts())
	if len(got) != 0 {
		t.Fatalf("a well-configured project produced findings: %+v", got)
	}
}

// ── THE HEADLINE EXPOSURE ────────────────────────────────────────────────────────────────────────

// Unprotected preview deployments: every PR publishes a public URL running production-like code.
// This is the finding the package exists for.
func TestUnprotectedPreview_IsHigh(t *testing.T) {
	got := Assess(Snapshot{Projects: []Project{{Name: "acme-web", PreviewProtected: b(false)}}}, opts())
	f := has(got, "preview-unprotected")
	if f == nil {
		t.Fatalf("an unprotected preview environment produced no finding: %+v", got)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	// It must name the project and tell them the specific setting to change.
	if !strings.Contains(f.Description, "acme-web") {
		t.Error("the finding does not name the project")
	}
	if !strings.Contains(strings.ToLower(f.Description), "deployment protection") {
		t.Errorf("the finding does not name the setting to change: %q", f.Description)
	}
	// And it must explain WHY a public URL matters, since "it's just a preview" is the natural dismissal.
	if !strings.Contains(strings.ToLower(f.Description), "certificate-transparency") {
		t.Errorf("the finding does not explain how the URL is discovered: %q", f.Description)
	}
}

// ── ABSENT CONFIG IS NOT INSECURE CONFIG ─────────────────────────────────────────────────────────

// THE REFUSAL THAT MATTERS. A snapshot that does not carry a setting must produce NOTHING. "We were
// not told" and "it is off" are different facts, and treating the first as the second invents a
// vulnerability out of an incomplete export.
func TestAbsentSettings_ProduceNoFindings(t *testing.T) {
	got := Assess(Snapshot{Projects: []Project{{
		Name:    "acme-web", // every protection field nil
		EnvVars: []EnvVar{{Key: "API_SECRET", Targets: []string{"production", "preview"}}},
	}}}, opts())
	if has(got, "preview-unprotected") != nil {
		t.Error("a project with NO preview setting was reported unprotected — that is an invented finding")
	}
	if has(got, "source-publicly-readable") != nil {
		t.Error("a project with NO source setting was reported public")
	}
	// The env-var finding is still legitimate: that one is derived from data the snapshot DID carry.
	if has(got, "production-secret-in-preview") == nil {
		t.Error("a real, stated env-var exposure was suppressed along with the unknowns")
	}
}

func TestIsFalse_DistinguishesAbsentFromOff(t *testing.T) {
	if isFalse(nil) {
		t.Error("nil (not told) was treated as false (off) — the whole refusal turns on this")
	}
	if !isFalse(b(false)) {
		t.Error("an explicit false was not recognised")
	}
	if isFalse(b(true)) {
		t.Error("true was treated as false")
	}
}

// ── PRODUCTION SECRETS IN PREVIEW ────────────────────────────────────────────────────────────────

func TestProductionSecretInPreview_IsFlaggedByKeyNotValue(t *testing.T) {
	got := Assess(Snapshot{Projects: []Project{{
		Name: "acme-web",
		EnvVars: []EnvVar{
			{Key: "STRIPE_SECRET_KEY", Targets: []string{"production", "preview"}},
			{Key: "DATABASE_URL", Targets: []string{"production", "preview"}},
		},
	}}}, opts())
	f := has(got, "production-secret-in-preview")
	if f == nil {
		t.Fatal("production credentials exposed to preview produced no finding")
	}
	if !strings.Contains(f.Description, "STRIPE_SECRET_KEY") || !strings.Contains(f.Description, "DATABASE_URL") {
		t.Errorf("the finding does not name the variables: %q", f.Description)
	}
}

// A variable scoped to production ONLY is correct configuration, not a finding.
func TestProductionOnlySecret_IsNotAFinding(t *testing.T) {
	got := Assess(Snapshot{Projects: []Project{{
		Name: "acme-web", EnvVars: []EnvVar{{Key: "STRIPE_SECRET_KEY", Targets: []string{"production"}}},
	}}}, opts())
	if has(got, "production-secret-in-preview") != nil {
		t.Error("a correctly-scoped production secret was flagged")
	}
}

// A shared FEATURE FLAG is not a credential. Flagging it is the noise that trains people to ignore
// the next finding — so the matcher is deliberately conservative.
func TestNonCredentialSharedVar_IsNotAFinding(t *testing.T) {
	got := Assess(Snapshot{Projects: []Project{{
		Name: "acme-web",
		EnvVars: []EnvVar{
			{Key: "NEXT_PUBLIC_SITE_URL", Targets: []string{"production", "preview"}},
			{Key: "FEATURE_NEW_NAV", Targets: []string{"production", "preview"}},
			{Key: "LOG_LEVEL", Targets: []string{"production", "preview"}},
		},
	}}}, opts())
	if f := has(got, "production-secret-in-preview"); f != nil {
		t.Errorf("a shared feature flag was reported as a leaked credential: %q", f.Description)
	}
}

func TestLooksLikeCredential_CoversRealNamesWithoutOverreaching(t *testing.T) {
	for _, yes := range []string{"STRIPE_SECRET_KEY", "DATABASE_URL", "api_key", "GITHUB_PAT", "CLIENT_SECRET", "SLACK_WEBHOOK_URL"} {
		if !looksLikeCredential(yes) {
			t.Errorf("%q was not recognised as a credential", yes)
		}
	}
	for _, no := range []string{"LOG_LEVEL", "FEATURE_NEW_NAV", "NEXT_PUBLIC_SITE_URL", "NODE_ENV", "PORT"} {
		if looksLikeCredential(no) {
			t.Errorf("%q was miscalled a credential — this is the noise that costs trust", no)
		}
	}
}

// ── NOT CRYING WOLF ──────────────────────────────────────────────────────────────────────────────

// An unprotected PRODUCTION site is usually intentional — it is a website. It is only reported
// alongside a real exposure, never on its own, because "your website is reachable from the internet"
// is exactly the finding that teaches someone to stop reading.
func TestUnprotectedProductionAlone_IsNotAFinding(t *testing.T) {
	got := Assess(Snapshot{Projects: []Project{{
		Name: "acme-web", ProductionProtected: b(false), PreviewProtected: b(true), PublicSource: b(true),
	}}}, opts())
	if len(got) != 0 {
		t.Errorf("a normal public website produced findings: %+v", got)
	}
}

// But open production PLUS readable source is a real combination.
func TestUnprotectedProductionWithPublicSource_IsReported(t *testing.T) {
	got := Assess(Snapshot{Projects: []Project{{
		Name: "acme-web", ProductionProtected: b(false), PublicSource: b(false),
		ProductionDomains: []string{"acme.com"},
	}}}, opts())
	f := has(got, "production-unprotected-with-public-source")
	if f == nil {
		t.Fatalf("open production + readable source produced no finding: %+v", got)
	}
	if !strings.Contains(f.Description, "acme.com") {
		t.Errorf("the finding does not name what is live: %q", f.Description)
	}
}

// ── HYGIENE ──────────────────────────────────────────────────────────────────────────────────────

func TestFindings_AreActionableAndOrdered(t *testing.T) {
	got := Assess(Snapshot{Projects: []Project{
		{Name: "low", ProductionProtected: b(false), PublicSource: b(false)},
		{Name: "high", PreviewProtected: b(false)},
	}}, opts())
	if len(got) < 2 {
		t.Fatalf("expected findings from both projects, got %d", len(got))
	}
	if got[0].Severity != types.SeverityHigh {
		t.Errorf("leads with %s; the high-severity preview exposure must come first", got[0].Severity)
	}
	for _, f := range got {
		if f.Endpoint == "" || !strings.HasPrefix(f.Endpoint, "vercel:") {
			t.Errorf("finding %s has no project-qualified endpoint: %q", f.RuleID, f.Endpoint)
		}
		if f.Compliance == nil || len(f.Compliance.SOC2) == 0 {
			t.Errorf("finding %s carries no compliance nexus", f.RuleID)
		}
		if f.Tool != "vercelposture" {
			t.Errorf("finding %s has tool %q", f.RuleID, f.Tool)
		}
	}
}

func TestDegenerateInput_IsSilent(t *testing.T) {
	if got := Assess(Snapshot{}, opts()); len(got) != 0 {
		t.Errorf("empty snapshot produced %d findings", len(got))
	}
	if got := Assess(Snapshot{Projects: []Project{{Name: "  ", PreviewProtected: b(false)}}}, opts()); len(got) != 0 {
		t.Errorf("an unnamed project produced findings")
	}
}

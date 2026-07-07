package bench

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// discoveryScenario: a noisy estate. Two findings create REAL impact (a cross-surface chain + a public PII
// bucket); the rest are noise (a critical RCE on a throwaway box, a medium on a marketing site).
func discoveryScenario() DiscoveryScenario {
	return DiscoveryScenario{ID: "estate", Findings: []DiscoveryFinding{
		{ID: "leaked-key", Surface: "code", Severity: types.SeverityMedium, HighImpact: true, ImpactType: ImpactLateral,
			Reaches: "PII bucket via cloud role", Detail: "AWS key in repo → assumable deploy role → customer-PII S3"},
		{ID: "public-pii", Surface: "cloud", Severity: types.SeverityHigh, HighImpact: true, ImpactType: ImpactDataExposure,
			Reaches: "customer PII", Detail: "S3 bucket with customer records is public"},
		{ID: "rce-devbox", Surface: "cloud", Severity: types.SeverityCritical, HighImpact: false,
			Detail: "RCE on an isolated throwaway CI box, no creds, torn down nightly"},
		{ID: "xss-marketing", Surface: "web", Severity: types.SeverityMedium, HighImpact: false,
			Detail: "reflected XSS on the public marketing microsite, no data"},
	}}
}

// TestScoreDiscovery_PerfectFindsImpactfulNotNoise: surfacing exactly the two impactful findings PASSES.
func TestScoreDiscovery_PerfectFindsImpactfulNotNoise(t *testing.T) {
	sc := discoveryScenario()
	d := EngineerDiscovery{HighImpactIDs: []string{"leaked-key", "public-pii"}}
	s := ScoreDiscovery(sc, d)
	if s.Recall != 1.0 || s.FP != 0 || s.FN != 0 || len(s.Invented) != 0 {
		t.Fatalf("perfect discovery: %s", RenderDiscoveryScore(s))
	}
	if !s.Pass() {
		t.Errorf("finding exactly the impactful findings must PASS: %s", RenderDiscoveryScore(s))
	}
	// per-category recall recorded.
	if s.ByType[ImpactLateral].Found != 1 || s.ByType[ImpactDataExposure].Found != 1 {
		t.Errorf("by-type recall wrong: %+v", s.ByType)
	}
}

// TestScoreDiscovery_MissingTheChainFails: missing the cross-surface chain (the hardest, highest-value
// find) drops recall below 1 — the worst failure for "find the vuln that creates real impact".
func TestScoreDiscovery_MissingTheChainFails(t *testing.T) {
	sc := discoveryScenario()
	d := EngineerDiscovery{HighImpactIDs: []string{"public-pii"}} // missed the leaked-key chain
	s := ScoreDiscovery(sc, d)
	if s.Recall >= 1.0 || len(s.Missed) != 1 || s.Missed[0] != "leaked-key" {
		t.Errorf("missing the chain must lower recall + flag it: %s", RenderDiscoveryScore(s))
	}
	if s.Pass() {
		t.Error("missing a real-impact finding must NOT pass")
	}
}

// TestScoreDiscovery_FlagEverythingFails: the gaming guard — flagging ALL findings as high-impact reaches
// recall 1 but generates false alarms (FP>0), so it must NOT pass. "Cry wolf on everything" is not discovery.
func TestScoreDiscovery_FlagEverythingFails(t *testing.T) {
	sc := discoveryScenario()
	d := EngineerDiscovery{HighImpactIDs: []string{"leaked-key", "public-pii", "rce-devbox", "xss-marketing"}}
	s := ScoreDiscovery(sc, d)
	if s.Recall != 1.0 {
		t.Errorf("flag-everything trivially has recall 1, got %.2f", s.Recall)
	}
	if s.FP != 2 {
		t.Errorf("the two noise findings flagged high must be false alarms, got FP=%d", s.FP)
	}
	if s.Pass() {
		t.Error("flag-everything must NOT pass — precision guards against crying wolf")
	}
}

// decoyScenario: a real chain PLUS two decoys that LOOK impactful but are provably broken — one by an
// explicit IAM deny (the tempting AssumeRole to PII is denied by a boundary), one by network
// unreachability (a critical RCE that fronts the DB but is VPN-only). Mirrors fixtures/discovery/
// estate-decoy.json. Tests PRECISION on chains: a "flag anything that touches a crown jewel" heuristic
// flags both decoys; only correct correlation dismisses them (§10 — don't invent impact).
func decoyScenario() DiscoveryScenario {
	return DiscoveryScenario{ID: "estate-decoy", Findings: []DiscoveryFinding{
		{ID: "key-in-lambda", Surface: "code", Severity: types.SeverityMedium, HighImpact: true, ImpactType: ImpactLateral,
			Reaches: "financial invoices bucket via role reporting", Detail: "leaked key → reporting → GetObject acme-invoices"},
		{ID: "key-in-terraform", Surface: "code", Severity: types.SeverityHigh, HighImpact: false,
			Detail: "leaked key → analytics; AssumeRole to data-admin (PII) is DENIED by a permission-boundary explicit deny"},
		{ID: "rce-adminpanel", Surface: "cloud", Severity: types.SeverityCritical, HighImpact: false,
			Detail: "RCE fronting the customer DB but reachable only from the VPN CIDR — no internet route"},
		{ID: "pub-brochures", Surface: "cloud", Severity: types.SeverityMedium, HighImpact: false,
			Detail: "public marketing brochures only"},
	}}
}

// TestScoreDiscovery_DecoyDismissed: flagging ONLY the real medium chain (dismissing the high+critical
// decoys) PASSES — the precision/grounding win. This is the "don't invent impact on a broken chain" test.
func TestScoreDiscovery_DecoyDismissed(t *testing.T) {
	sc := decoyScenario()
	d := EngineerDiscovery{HighImpactIDs: []string{"key-in-lambda"}}
	s := ScoreDiscovery(sc, d)
	if !s.Pass() || s.Recall != 1.0 || s.FP != 0 {
		t.Fatalf("dismissing the broken decoys while finding the real chain must PASS: %s", RenderDiscoveryScore(s))
	}
}

// TestScoreDiscovery_DecoyFlaggedIsFalseAlarm: the "any hop touches a crown jewel" heuristic flags both
// decoys → recall 1 but precision drops (FP>0), so it must NOT pass. This is the core of the decoy test:
// severity/reachability-to-a-jewel is not enough; the chain must actually RESOLVE.
func TestScoreDiscovery_DecoyFlaggedIsFalseAlarm(t *testing.T) {
	sc := decoyScenario()
	d := EngineerDiscovery{HighImpactIDs: []string{"key-in-lambda", "key-in-terraform", "rce-adminpanel"}}
	s := ScoreDiscovery(sc, d)
	if s.Recall != 1.0 {
		t.Errorf("flagging the real chain reaches recall 1, got %.2f", s.Recall)
	}
	if s.FP != 2 {
		t.Errorf("the two broken decoys flagged high must be false alarms, got FP=%d", s.FP)
	}
	if s.Pass() {
		t.Error("flagging the broken decoys must NOT pass — precision guards against invented chain-impact")
	}
}

// TestScoreDiscovery_PerCategoryCorrelation: the privesc + external-exposure correlation scenarios. Each
// has one real chain (only derivable from the raw facts) + a decoy that a naive severity/keyword read
// flags. Finding exactly the real one PASSES with the right category; flagging the decoy is a false alarm.
// Mirrors fixtures/discovery/estate-privesc.json + estate-external.json.
func TestScoreDiscovery_PerCategoryCorrelation(t *testing.T) {
	cases := []struct {
		name     string
		sc       DiscoveryScenario
		real     string
		realType ImpactType
		decoy    string // a plausible-but-wrong finding a naive ranker flags
	}{
		{
			name:     "privilege_escalation",
			real:     "key-in-jenkins", realType: ImpactPrivEsc, decoy: "key-in-notebook",
			sc: DiscoveryScenario{ID: "privesc", Findings: []DiscoveryFinding{
				{ID: "key-in-jenkins", Severity: types.SeverityMedium, HighImpact: true, ImpactType: ImpactPrivEsc,
					Detail: "leaked key → ci-build → PassRole+Lambda → account admin"},
				{ID: "key-in-notebook", Severity: types.SeverityMedium, HighImpact: false, Detail: "leaked key → analyst → public bucket only"},
			}},
		},
		{
			name:     "external_exposure",
			real:     "open-orders-db", realType: ImpactExternal, decoy: "open-bastion",
			sc: DiscoveryScenario{ID: "external", Findings: []DiscoveryFinding{
				{ID: "open-orders-db", Severity: types.SeverityHigh, HighImpact: true, ImpactType: ImpactExternal,
					Detail: "SG 0.0.0.0/0 on 5432 → financial DB"},
				{ID: "open-bastion", Severity: types.SeverityHigh, HighImpact: false, Detail: "internet SSH but no key + fronts nothing"},
			}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			good := ScoreDiscovery(c.sc, EngineerDiscovery{HighImpactIDs: []string{c.real}})
			if !good.Pass() || good.ByType[c.realType].Found != 1 {
				t.Fatalf("finding the real %s chain must PASS in-category: %s", c.name, RenderDiscoveryScore(good))
			}
			bad := ScoreDiscovery(c.sc, EngineerDiscovery{HighImpactIDs: []string{c.decoy}})
			if bad.FP != 1 || bad.Pass() {
				t.Errorf("flagging the decoy %q must be a false alarm + not pass: %s", c.decoy, RenderDiscoveryScore(bad))
			}
		})
	}
}

// TestScoreDiscovery_VolumePrecision: at realistic backlog volume the scary-but-contained noise (a
// critical Log4Shell in a test fixture, a high devbox CVE) is the precision trap. Flagging the real
// buried impacts PASSES; a severity-first top-N that grabs the scary noise fails on both recall and
// precision. Guards against a "tiny 4-finding estate" overfit. Mirrors fixtures/discovery/estate-backlog.
func TestScoreDiscovery_VolumePrecision(t *testing.T) {
	// a compact stand-in: 3 real buried impacts + 3 scary-but-contained noise (higher-severity than the real).
	sc := DiscoveryScenario{ID: "backlog", Findings: []DiscoveryFinding{
		{ID: "leaked-db", Severity: types.SeverityMedium, HighImpact: true, ImpactType: ImpactDataExposure, Detail: "creds → prod PII DB"},
		{ID: "key-privesc", Severity: types.SeverityMedium, HighImpact: true, ImpactType: ImpactPrivEsc, Detail: "key → CreateAccessKey * → admin"},
		{ID: "ssrf-pii", Severity: types.SeverityMedium, HighImpact: true, ImpactType: ImpactLateral, Detail: "SSRF → IMDSv1 → PII bucket"},
		{ID: "log4j-testfixture", Severity: types.SeverityCritical, HighImpact: false, Detail: "log4j in test fixtures, not shipped"},
		{ID: "openssl-devbox", Severity: types.SeverityHigh, HighImpact: false, Detail: "CVE on a recycled devbox, no prod route"},
		{ID: "default-creds-staging", Severity: types.SeverityHigh, HighImpact: false, Detail: "admin/admin on VPN-only staging, empty data"},
	}}
	good := ScoreDiscovery(sc, EngineerDiscovery{HighImpactIDs: []string{"leaked-db", "key-privesc", "ssrf-pii"}})
	if !good.Pass() || good.Recall != 1.0 || good.FP != 0 {
		t.Fatalf("finding the 3 buried real impacts must PASS: %s", RenderDiscoveryScore(good))
	}
	// severity-first grabs the 3 scary noise items → misses every real one, all false alarms.
	sev := ScoreDiscovery(sc, EngineerDiscovery{HighImpactIDs: []string{"log4j-testfixture", "openssl-devbox", "default-creds-staging"}})
	if sev.Recall != 0 || sev.FP != 3 || sev.Pass() {
		t.Errorf("severity-first must miss all real + flag 3 noise: %s", RenderDiscoveryScore(sev))
	}
}

// TestScoreDiscovery_CrossSurfaceCombination: two individually-low findings that only reach a crown jewel
// TOGETHER (a push-only registry token + a prod cluster that auto-deploys :latest → prod-secrets RCE). Both
// must be flagged (each is half the impact). A structurally-identical but non-joining pair (a read-only
// token + a staging deploy) must be dismissed. Every finding is low-severity, so this is pure composition
// reasoning — severity/keyword ranking cannot separate them. Mirrors fixtures/discovery/estate-combo.json.
func TestScoreDiscovery_CrossSurfaceCombination(t *testing.T) {
	sc := DiscoveryScenario{ID: "combo", Findings: []DiscoveryFinding{
		{ID: "push-token", Severity: types.SeverityLow, HighImpact: true, ImpactType: ImpactLateral, Detail: "ecr:PutImage on acme/web"},
		{ID: "prod-deploy", Severity: types.SeverityLow, HighImpact: true, ImpactType: ImpactLateral, Detail: "prod auto-deploys acme/web:latest, node role has prod secrets"},
		{ID: "ro-token", Severity: types.SeverityLow, HighImpact: false, Detail: "read-only metrics token, joins nothing"},
		{ID: "staging-deploy", Severity: types.SeverityLow, HighImpact: false, Detail: "staging auto-deploy, no secrets, no prod route"},
	}}
	// composing the two halves PASSES.
	good := ScoreDiscovery(sc, EngineerDiscovery{HighImpactIDs: []string{"push-token", "prod-deploy"}})
	if !good.Pass() || good.ByType[ImpactLateral].Found != 2 {
		t.Fatalf("composing the two halves must PASS with both surfaced: %s", RenderDiscoveryScore(good))
	}
	// flagging only one half misses the composition (recall < 1).
	half := ScoreDiscovery(sc, EngineerDiscovery{HighImpactIDs: []string{"push-token"}})
	if half.Recall >= 1.0 || half.Pass() {
		t.Errorf("flagging one half must miss the composition: %s", RenderDiscoveryScore(half))
	}
	// flagging the structurally-identical non-joining pair too is a false alarm (precision < 1).
	over := ScoreDiscovery(sc, EngineerDiscovery{HighImpactIDs: []string{"push-token", "prod-deploy", "ro-token", "staging-deploy"}})
	if over.FP != 2 || over.Pass() {
		t.Errorf("flagging the non-joining decoys must be false alarms: %s", RenderDiscoveryScore(over))
	}
}

// TestScoreDiscovery_CleanEstateFloor: a hardened all-noise estate — the correct answer is FLAG NOTHING.
// Flagging nothing PASSES (the precision floor); crying wolf on the scary critical/high (grounded as
// contained) is a false alarm and must NOT pass. This is the §10 "don't manufacture impact" test at the
// estate level — the complement every recall test misses (an always-flag-nothing engineer passes here but
// fails every other scenario; an over-flagger fails here). Mirrors fixtures/discovery/estate-clean.json.
func TestScoreDiscovery_CleanEstateFloor(t *testing.T) {
	sc := DiscoveryScenario{ID: "clean", Findings: []DiscoveryFinding{
		{ID: "critical-airgapped", Severity: types.SeverityCritical, HighImpact: false, Detail: "CVE on an air-gapped box, no network"},
		{ID: "admin-sso-mfa", Severity: types.SeverityHigh, HighImpact: false, Detail: "internet admin panel but SSO+MFA, IP-allowlisted"},
		{ID: "headers", Severity: types.SeverityLow, HighImpact: false, Detail: "missing security headers"},
	}}
	// flag nothing → the correct answer → PASS (recall vacuously 1, no false alarms).
	clean := ScoreDiscovery(sc, EngineerDiscovery{})
	if !clean.Pass() || clean.FP != 0 {
		t.Fatalf("flagging nothing on a clean estate must PASS: %s", RenderDiscoveryScore(clean))
	}
	// crying wolf on the scary-but-contained critical/high → false alarms → must NOT pass.
	wolf := ScoreDiscovery(sc, EngineerDiscovery{HighImpactIDs: []string{"critical-airgapped", "admin-sso-mfa"}})
	if wolf.FP != 2 || wolf.Pass() {
		t.Errorf("crying wolf on contained findings must be false alarms + not pass: %s", RenderDiscoveryScore(wolf))
	}
}

// TestScoreDiscovery_InventedFails: claiming a finding not in the estate is a hallucination (§10).
func TestScoreDiscovery_InventedFails(t *testing.T) {
	sc := discoveryScenario()
	d := EngineerDiscovery{HighImpactIDs: []string{"leaked-key", "public-pii", "ghost"}}
	s := ScoreDiscovery(sc, d)
	if len(s.Invented) != 1 || s.Invented[0] != "ghost" || s.Pass() {
		t.Errorf("an invented finding must be flagged + block pass: %s", RenderDiscoveryScore(s))
	}
}

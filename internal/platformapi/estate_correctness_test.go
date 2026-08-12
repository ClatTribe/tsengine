package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// T6 is the one task where being WRONG is worse than being absent. An engineer asking "are we exposed
// to X?" acts on the answer; a search that quietly omits a match produces a false all-clear about the
// customer's own estate, and nothing downstream can tell that from a genuinely clean result.
//
// The self-test proved the path runs. These prove the ANSWERS are right.

func estateWith(t *testing.T, fs ...types.Finding) (Deps, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	const tid = "t1"
	if err := st.PutTenant(ctx, platform.Tenant{ID: tid}); err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if err := st.PutFinding(ctx, tid, f); err != nil {
			t.Fatal(err)
		}
	}
	return Deps{Store: st}, tid
}

func mk(id, tool, rule, title, endpoint, desc string, sev types.Severity, vs types.VerificationState) types.Finding {
	return types.Finding{
		ID: id, Tool: tool, RuleID: rule, Title: title, Endpoint: endpoint,
		Description: desc, Severity: sev, VerificationStatus: vs,
	}
}

// "Are we exposed to log4j?" — the canonical question, and the one where a miss is a false all-clear.
func TestT6_FindsAMatchAnywhereInTheFinding(t *testing.T) {
	d, tid := estateWith(t,
		mk("f1", "grype", "CVE-2021-44228", "Remote code execution in logging library",
			"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			"The bundled version is affected by the JNDI lookup flaw.", types.SeverityCritical, types.VerificationPatternMatch),
		mk("f2", "nuclei", "missing-hsts", "Missing HSTS header", "https://a.example/", "", types.SeverityLow, types.VerificationPatternMatch),
	)
	got, err := (estateSearch{d: d, tenantID: tid}).Search(context.Background(), "log4j")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "f1") {
		t.Errorf("T6 WRONG: a log4j finding was not returned for the query 'log4j' — this is a FALSE "+
			"ALL-CLEAR about the customer's own estate:\n%s", got)
	}
}

// A query matching nothing must not sweep unrelated findings in. An over-broad answer is how an
// engineer ends up chasing the wrong thing.
func TestT6_DoesNotReturnUnrelatedFindings(t *testing.T) {
	d, tid := estateWith(t,
		mk("f1", "nuclei", "missing-hsts", "Missing HSTS header", "https://a.example/", "", types.SeverityLow, types.VerificationPatternMatch),
	)
	got, _ := (estateSearch{d: d, tenantID: tid}).Search(context.Background(), "kubernetes privilege escalation")
	if strings.Contains(got, "f1") {
		t.Errorf("T6 WRONG: an unrelated finding was returned:\n%s", got)
	}
}

// The counts in the header are read as fact. If they disagree with the rows, the answer is untrustworthy.
func TestT6_CountsMatchTheRowsShown(t *testing.T) {
	d, tid := estateWith(t,
		mk("f1", "nuclei", "sqli", "SQL injection", "https://a.example/s", "", types.SeverityCritical, types.VerificationPatternMatch),
		mk("f2", "nuclei", "sqli", "SQL injection two", "https://a.example/t", "", types.SeverityCritical, types.VerificationPatternMatch),
		mk("f3", "nuclei", "hsts", "Missing HSTS", "https://a.example/", "", types.SeverityLow, types.VerificationPatternMatch),
	)
	got, _ := (estateSearch{d: d, tenantID: tid}).Search(context.Background(), "critical injection")
	if !strings.Contains(got, "2 of 3 findings match") {
		t.Errorf("T6 WRONG: the header count disagrees with reality (want 2 of 3):\n%s", got)
	}
}

// Severity ordering: an engineer reading a truncated list must see the worst first.
func TestT6_WorstFirst(t *testing.T) {
	d, tid := estateWith(t,
		mk("low", "nuclei", "injection-note", "Injection note", "https://a.example/1", "", types.SeverityLow, types.VerificationPatternMatch),
		mk("crit", "nuclei", "injection-rce", "Injection RCE", "https://a.example/2", "", types.SeverityCritical, types.VerificationPatternMatch),
	)
	got, _ := (estateSearch{d: d, tenantID: tid}).Search(context.Background(), "injection")
	ci, li := strings.Index(got, "crit"), strings.Index(got, "low")
	if ci < 0 || li < 0 {
		t.Fatalf("both findings should match:\n%s", got)
	}
	if ci > li {
		t.Errorf("T6 WRONG: the low-severity finding was listed before the critical one:\n%s", got)
	}
}

// "unproven" must exclude what has been proven, or the engineer re-works settled findings.
func TestT6_UnprovenExcludesVerified(t *testing.T) {
	d, tid := estateWith(t,
		mk("proven", "nuclei", "sqli", "SQL injection proven", "https://a.example/1", "", types.SeverityCritical, types.VerificationVerified),
		mk("open", "nuclei", "sqli", "SQL injection open", "https://a.example/2", "", types.SeverityCritical, types.VerificationPatternMatch),
	)
	got, _ := (estateSearch{d: d, tenantID: tid}).Search(context.Background(), "unproven injection")
	if strings.Contains(got, "proven]") && !strings.Contains(got, "[open]") {
		t.Errorf("T6 WRONG: 'unproven' returned the verified finding:\n%s", got)
	}
	if !strings.Contains(got, "open") {
		t.Errorf("T6 WRONG: 'unproven' omitted the genuinely unproven finding:\n%s", got)
	}
}

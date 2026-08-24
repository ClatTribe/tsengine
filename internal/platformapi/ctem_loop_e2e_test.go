package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/retest"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/internal/webagent"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ctem_loop_e2e_test.go is ADR 0029 D3a: ONE test that walks the product sentence.
//
//	find → prove by exploiting → fix → re-attack to prove the fix held → compliance evidence
//
// Every stage of that had good tests and the sentence had none, which is how D1 shipped for months:
// each package was correct and the seam between two of them was not. This walks the seam.
//
// WHAT IT DOES NOT COVER, stated so nobody reads it as more than it is: the runner's SCHEDULING of
// the last two steps — that it calls retest.Verify and then the Reattacker on every monitoring pass,
// and skips both on a degraded pass — is covered by runner/reattack_loop_test.go and
// runner/unscanned_not_fixed_test.go. This test drives the same two functions the runner drives, in
// the same order, but it is not the runner. No single test spans both packages, and that residual is
// deliberate rather than overlooked: runner cannot import platformapi.

// stillWorkingProber answers as a vulnerable app does: the injected object comes back.
type stillWorkingProber struct{ sent int }

func (p *stillWorkingProber) Send(_ context.Context, _ pentest.Probe) (pentest.ProbeResult, error) {
	p.sent++
	return pentest.ProbeResult{Status: 200, Body: "owner: another tenant"}, nil
}

func TestCTEMLoop_ProveFixReattackAndTheEvidence(t *testing.T) {
	t.Setenv("TSENGINE_L15_DISABLED", "")
	ctx := context.Background()
	st := store.NewMemory()

	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Plan: platform.PlanEnterprise}) // AI enabled
	_ = st.PutAsset(ctx, platform.Asset{
		ID: "a1", TenantID: "t1", Type: "web_application", Target: "app.acme.com",
		Meta: map[string]string{"ownership_verified": "true"}, // the re-attack gate
	})

	// The agent finds a BOLA it actually demonstrated. This class is the one that matters here: its
	// re-test probes the URL verbatim, so it is the class the identity normalisation would have broken.
	fd := &fakeDiscoverer{ret: []webagent.Finding{{
		ID: "d1", Route: "https://app.acme.com/orders?id=1041", Class: "idor",
		Rationale: "another tenant's order returned", Verified: true,
	}}}
	prober := &stillWorkingProber{}
	d := Deps{
		Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		AgentLLM:      fakeCloudLLM{},
		WebDiscoverer: fd.run,
		GRC:           &grc.GRC{Store: st, ControlUniverse: hooks.NewCompliance().ControlsFor},
		Prober:        prober,
	}
	h := NewHandler(d)

	// ── 1. FIND + PROVE ───────────────────────────────────────────────────────────────────────────
	eng := `{"name":"e2e","mode":"active","rules_of_engagement":{"authorized_targets":["app.acme.com"],` +
		`"max_requests":40,"allow_active":true,"authorized_by":"alice","consent":"authorized by alice","target_environment":"staging"}}`
	var created struct {
		ID string `json:"id"`
	}
	rec := do(h, "POST", "/v1/pentest", "t1", eng)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("create engagement: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if run := do(h, "POST", "/v1/pentest/"+created.ID+"/run", "t1", ""); run.Code != http.StatusOK {
		t.Fatalf("run: %d %s", run.Code, run.Body.String())
	}

	all, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	var proven types.Finding
	for _, f := range all {
		if f.Tool == "web-investigate" {
			proven = f
		}
	}
	if proven.ID == "" {
		t.Fatal("the proven finding was not persisted — nothing downstream can happen")
	}
	if proven.VerificationStatus != types.VerificationVerified {
		t.Errorf("a demonstrated exploit is stored as %q, want verified", proven.VerificationStatus)
	}

	// ── 2. THE EVIDENCE, FROM THE SAME RUN ────────────────────────────────────────────────────────
	// This is the clause D1 existed to make true. Before it, everything above worked and this failed.
	if proven.Compliance == nil {
		t.Fatal("the proven finding carries no control mapping — it never went through the L1.5 chain")
	}
	states, err := d.GRC.Posture(ctx, "t1", "soc2")
	if err != nil {
		t.Fatalf("posture: %v", err)
	}
	var gaps int
	for _, cs := range states {
		if cs.State == platform.ControlGap {
			gaps++
		}
	}
	if gaps == 0 {
		t.Error("a vulnerability we EXPLOITED opened no SOC 2 control gap. The posture reads clean for a " +
			"hole we just proved is real — the false-compliant mode ADR 0029 D1a closes.")
	}

	// ── 3. FIX ────────────────────────────────────────────────────────────────────────────────────
	// A remediation was applied and claims to close this finding. The key is what carries the claim
	// across scans, exactly as runner.stampFindingKeys records it at propose time.
	key := detect.Key(proven)
	applied := platform.Action{
		ID: "act1", TenantID: "t1", Kind: platform.ActOpenPR, Status: platform.ActApplied,
		FindingID: proven.ID, FindingKeys: []string{key},
	}
	if err := st.PutAction(ctx, applied); err != nil {
		t.Fatalf("put action: %v", err)
	}

	// ── 4. RE-ATTACK ──────────────────────────────────────────────────────────────────────────────
	// The two calls the runner makes, in the order it makes them (runner.go: retest.Verify, then the
	// Reattacker, then retest.ApplyReattack over the merged set).
	verdicts := d.ReattackVerdicts(ctx, "t1", []string{key})
	v, ok := verdicts[key]
	if !ok {
		t.Fatal("the re-attack adapter returned no verdict for an applied fix's finding key")
	}
	if !v.Verified {
		t.Fatalf("the re-attack did not run: %s", v.Evidence)
	}
	if prober.sent == 0 {
		t.Error("no probe was sent — the exploit was not actually re-run")
	}
	if !v.Exploitable {
		t.Error("the app still returns another tenant's order, so the exploit STILL WORKS. Reporting " +
			"anything else here is the false all-clear this loop exists to prevent.")
	}

	updated := retest.ApplyReattack([]platform.Action{applied}, verdicts, time.Now().UTC())
	if len(updated) != 1 {
		t.Fatalf("expected the action to be updated with a re-attack verdict, got %d", len(updated))
	}
	fv := updated[0].Verification
	if fv == nil {
		t.Fatal("no fix verification was recorded on the applied action")
	}
	if fv.Status != retest.StatusStillExploitable {
		t.Errorf("fix verification says %q; the exploit still works, so it must say %q",
			fv.Status, retest.StatusStillExploitable)
	}
	if fv.Method != retest.MethodReattack {
		t.Errorf("verification method is %q — a verdict from re-running the exploit must be recorded as "+
			"%q, so a reader can tell it apart from a scanner's silence", fv.Method, retest.MethodReattack)
	}

	// ── 5. THE PROVING REQUEST SURVIVED THE WHOLE JOURNEY ─────────────────────────────────────────
	// The identity-normalised endpoint is what the store holds; the exact URL is what the re-attack
	// needs. Both have to be true at the end of the loop, not just at the start.
	if strings.Contains(proven.Endpoint, "id=1041") {
		t.Error("the stored endpoint kept the payload value — identity would then change every scan, " +
			"and incidents would churn (see hooks/cross_tool_merge)")
	}
	if got := proven.ToolArgs["exploit_url"]; !strings.Contains(got, "id=1041") {
		t.Errorf("the exact proving URL did not survive to the store: %q. Without it the re-attack "+
			"probes a valueless parameter and reads the empty answer as closure.", got)
	}
}

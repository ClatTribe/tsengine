package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ══ THE SAFETY GATES ═════════════════════════════════════════════════════════════════════════════
//
// A re-attack fires a REAL payload at a customer's running system, on a schedule, with nobody
// clicking anything. These tests exist because that is a materially different act from reading a
// catalog, and both gates must fail CLOSED and fail HONESTLY.

type stubProber struct {
	body string
	sent int
}

func (p *stubProber) Send(_ context.Context, _ pentest.Probe) (pentest.ProbeResult, error) {
	p.sent++
	return pentest.ProbeResult{Status: 200, Body: p.body}, nil
}

func xssFinding() types.Finding {
	return types.Finding{
		ID: "f-1", RuleID: "nuclei::reflected-xss", Tool: "nuclei", Severity: types.SeverityHigh,
		CWE: []string{"CWE-79"}, Title: "Reflected XSS", Endpoint: "https://app.acme.com/search?q=x",
	}
}

// seedTenant stores a finding, and an asset whose ownership is verified or not.
func seedTenant(t *testing.T, ownershipVerified bool) (Deps, string, *stubProber) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	const tid = "tenant-abcd"
	// Enterprise: re-attack is the AI Pentester's capability, so the tenant must be entitled to it.
	// The gate itself is asserted separately below.
	if err := st.PutTenant(ctx, platform.Tenant{ID: tid, Plan: platform.PlanEnterprise}); err != nil {
		t.Fatal(err)
	}
	f := xssFinding()
	if err := st.PutFinding(ctx, tid, f); err != nil {
		t.Fatal(err)
	}
	a := platform.Asset{ID: "a1", TenantID: tid, Type: "web_application", Target: "app.acme.com"}
	if ownershipVerified {
		a.Meta = map[string]string{"ownership_verified": "true"}
	}
	if err := st.PutAsset(ctx, a); err != nil {
		t.Fatal(err)
	}
	p := &stubProber{body: "nothing reflected"}
	return Deps{Store: st, Prober: p}, tid, p
}

// GATE 1: no live probing enabled → nothing is sent, and the verdict is UNVERIFIED (not "clean").
func TestReattackVerdicts_NoProberSendsNothingAndSaysSo(t *testing.T) {
	d, tid, _ := seedTenant(t, true)
	d.Prober = nil
	key := detect.Key(xssFinding())

	got := d.ReattackVerdicts(context.Background(), tid, []string{key})
	v, ok := got[key]
	if !ok {
		t.Fatal("no verdict returned")
	}
	if v.Verified {
		t.Error("a deployment with no prober reported a VERIFIED verdict")
	}
	if v.Exploitable {
		t.Error("a finding that was never probed was marked exploitable")
	}
	if !strings.Contains(strings.ToLower(v.Evidence), "not enabled") {
		t.Errorf("evidence does not explain why nothing ran: %q", v.Evidence)
	}
}

// GATE 2, THE ONE THAT MATTERS: an unverified-ownership target is NEVER probed. Verifying a fix is
// not a reason to send payloads at a host nobody proved they own.
func TestReattackVerdicts_UnownedTargetIsNeverProbed(t *testing.T) {
	d, tid, p := seedTenant(t, false) // ownership NOT verified
	key := detect.Key(xssFinding())

	got := d.ReattackVerdicts(context.Background(), tid, []string{key})
	if p.sent != 0 {
		t.Fatalf("SENT %d PROBES AT A TARGET NOBODY PROVED THEY OWN", p.sent)
	}
	v := got[key]
	if v.Verified {
		t.Error("an un-probed finding was reported as verified")
	}
	if !strings.Contains(strings.ToLower(v.Evidence), "ownership") {
		t.Errorf("evidence does not name the ownership gate: %q", v.Evidence)
	}
}

// The positive case: an owned target IS probed, and the verdict is real.
func TestReattackVerdicts_OwnedTargetIsProbed(t *testing.T) {
	d, tid, p := seedTenant(t, true)
	key := detect.Key(xssFinding())

	got := d.ReattackVerdicts(context.Background(), tid, []string{key})
	if p.sent == 0 {
		t.Fatal("an ownership-verified target was not probed — the loop cannot close")
	}
	v := got[key]
	if !v.Verified {
		t.Errorf("a completed probe produced an unverified verdict: %+v", v)
	}
	if v.Exploitable {
		t.Error("the canary was not reflected, yet the finding was reported still-exploitable")
	}
}

// A key whose finding is no longer on record cannot have its exploit rebuilt — unverified, never
// assumed closed.
func TestReattackVerdicts_UnknownKeyIsUnverified(t *testing.T) {
	d, tid, _ := seedTenant(t, true)
	got := d.ReattackVerdicts(context.Background(), tid, []string{"gone::rule|nowhere"})
	v := got["gone::rule|nowhere"]
	if v.Verified {
		t.Error("a key with no stored finding was reported verified")
	}
	if !strings.Contains(strings.ToLower(v.Evidence), "no longer on record") {
		t.Errorf("evidence does not explain the missing finding: %q", v.Evidence)
	}
}

// EVERY skipped path must produce Verified=false, because retest.ApplyReattack treats that as "change
// nothing" while a true value would silently overwrite a rescan verdict.
func TestReattackVerdicts_EverySkipIsUnverified(t *testing.T) {
	for name, setup := range map[string]func() (Deps, string){
		"no prober": func() (Deps, string) { d, tid, _ := seedTenant(t, true); d.Prober = nil; return d, tid },
		"unowned":   func() (Deps, string) { d, tid, _ := seedTenant(t, false); return d, tid },
	} {
		d, tid := setup()
		for k, v := range d.ReattackVerdicts(context.Background(), tid, []string{detect.Key(xssFinding())}) {
			if v.Verified {
				t.Errorf("%s: key %s came back verified from a skipped path", name, k)
			}
			if v.Evidence == "" {
				t.Errorf("%s: key %s was skipped with no explanation", name, k)
			}
		}
	}
}

func TestOwnsEndpoint_FailsClosed(t *testing.T) {
	owned := []string{"app.acme.com"}
	if ownsEndpoint("https://app.acme.com/x", owned) != true {
		t.Error("an owned target was rejected")
	}
	if ownsEndpoint("https://evil.example/x", owned) {
		t.Error("an UNOWNED target was accepted — payloads would be sent at someone else's host")
	}
	if ownsEndpoint("", owned) {
		t.Error("an empty endpoint was treated as owned")
	}
	if ownsEndpoint("https://app.acme.com/x", nil) {
		t.Error("with NO owned targets, everything was treated as owned — the gate is inverted")
	}
}

func TestReattackVerdicts_EmptyInputIsNil(t *testing.T) {
	d, tid, _ := seedTenant(t, true)
	if got := d.ReattackVerdicts(context.Background(), tid, nil); got != nil {
		t.Errorf("no keys should yield nil, got %v", got)
	}
}

// GATE 0: re-attack is the AI Pentester's capability, and it is SOLD as the Growth tier
// ("re-tests after every fix"). A tenant without the pentester must not get it — otherwise the
// pricing page describes a product we do not ship, and a customer who turned the pentester off gets
// exploits fired on their behalf anyway.
func TestReattackVerdicts_RequiresThePentesterEntitlement(t *testing.T) {
	ctx := context.Background()
	d, tid, p := seedTenant(t, true)
	// Downgrade to the engineer-only tier.
	tn, _ := d.Store.GetTenant(ctx, tid)
	tn.Plan = platform.PlanGrowth // Core: engineer yes, pentester no
	if err := d.Store.PutTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	key := detect.Key(xssFinding())

	got := d.ReattackVerdicts(ctx, tid, []string{key})
	if p.sent != 0 {
		t.Fatalf("SENT %d PROBES for a tenant without the AI Pentester — the tier sells this capability", p.sent)
	}
	v := got[key]
	if v.Verified {
		t.Error("an un-probed finding was reported verified")
	}
	if !strings.Contains(strings.ToLower(v.Evidence), "ai pentester") {
		t.Errorf("evidence does not name the missing capability: %q", v.Evidence)
	}
}

// And the customer's own choice is honoured: someone who turned the pentester OFF does not get
// exploits fired on their behalf, even on an entitled plan.
func TestReattackVerdicts_RespectsTheCustomersAIModeChoice(t *testing.T) {
	ctx := context.Background()
	d, tid, p := seedTenant(t, true)
	tn, _ := d.Store.GetTenant(ctx, tid)
	tn.AIMode = platform.AIModeEngineer // entitled to both, chose engineer only
	if err := d.Store.PutTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	d.ReattackVerdicts(ctx, tid, []string{detect.Key(xssFinding())})
	if p.sent != 0 {
		t.Fatalf("SENT %d PROBES after the customer turned the pentester off", p.sent)
	}
}

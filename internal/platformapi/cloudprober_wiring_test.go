package platformapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// recordingProber notes that it was CONSTRUCTED for a tenant, which is the property under test — not
// that it answers correctly, which cloudprobe's own tests cover.
type recordingProber struct{ conn platform.Connection }

func (recordingProber) CanPerform(context.Context, string, string, string) (cloudagent.ProbeResult, error) {
	return cloudagent.ProbeResult{Verdict: cloudagent.VerdictUnknown}, nil
}
func (recordingProber) Coverage() string { return "recording" }

func withAWSConnection(t *testing.T, st store.Store, tenantID string, status string) {
	t.Helper()
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: tenantID, Plan: platform.PlanEnterprise}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutConnection(ctx, platform.Connection{
		ID: "c-aws", TenantID: tenantID, Kind: platform.ConnAWS,
		Account: "111122223333", SecretRef: "arn:aws:iam::111122223333:role/tsengine-read",
		Status: status,
	}); err != nil {
		t.Fatal(err)
	}
}

// THE WIRING IS THE POINT (ADR 0024 P1a's remaining half). The adapter and its refusals were tested
// in cloudprobe; what was missing is anything CONSTRUCTING it, which is C11's defect — a correct,
// tested primitive nothing calls, while the documents start describing it as though something does.
func TestProberOrNil_BuildsForAConnectedTenant(t *testing.T) {
	st := store.NewMemory()
	withAWSConnection(t, st, "t1", platform.ConnActive)

	var got platform.Connection
	d := Deps{Store: st, Connectors: connector.NewRegistry(),
		CloudProber: func(c platform.Connection) cloudagent.ExploitProber {
			got = c
			return recordingProber{conn: c}
		}}

	if p := d.proberOrNil(context.Background(), "t1"); p == nil {
		t.Fatal("a tenant with an active AWS connection got no prober, so every path stays config-possible")
	}
	// The role IS the credential and the tenant id IS the external-id guard, so both must reach the
	// constructor or it would assume the wrong role — or none.
	if got.SecretRef != "arn:aws:iam::111122223333:role/tsengine-read" || got.TenantID != "t1" {
		t.Fatalf("the connection did not reach the constructor intact: %+v", got)
	}
}

// Nil is a FIRST-CLASS answer, not a failure. Most tenants have no connected account, and a
// deployment may have no live AWS path at all; check_reachable then says the provider was not asked,
// rather than reporting a path proven or unproven (§10).
func TestProberOrNil_NilWhenThereIsNothingToAsk(t *testing.T) {
	built := func(c platform.Connection) cloudagent.ExploitProber { return recordingProber{} }

	t.Run("no constructor wired in this deployment", func(t *testing.T) {
		st := store.NewMemory()
		withAWSConnection(t, st, "t1", platform.ConnActive)
		d := Deps{Store: st, Connectors: connector.NewRegistry()} // CloudProber nil
		if d.proberOrNil(context.Background(), "t1") != nil {
			t.Fatal("built a prober with no constructor")
		}
	})

	t.Run("tenant has no connected account", func(t *testing.T) {
		st := store.NewMemory()
		_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1"})
		d := Deps{Store: st, Connectors: connector.NewRegistry(), CloudProber: built}
		if d.proberOrNil(context.Background(), "t1") != nil {
			t.Fatal("built a prober for a tenant with no AWS connection")
		}
	})

	// A revoked or quarantined connection must not be probed through: OM-5 fail-closed. Acting on a
	// connection the customer has withdrawn is exactly what the flag exists to stop.
	t.Run("connection is not active", func(t *testing.T) {
		st := store.NewMemory()
		withAWSConnection(t, st, "t1", platform.ConnRevoked)
		d := Deps{Store: st, Connectors: connector.NewRegistry(), CloudProber: built}
		if d.proberOrNil(context.Background(), "t1") != nil {
			t.Fatal("built a prober over a revoked connection")
		}
	})
}

// ProbeStamp's LAYOUT is load-bearing, not cosmetic: ADR 0024 P1c parses it to age a proof, so a
// differently-formatted stamp makes every proof's age unreadable and therefore StandingUnknown —
// silently turning the freshness work into a no-op.
func TestProbeStamp_ParsesAsTheFreshnessContractExpects(t *testing.T) {
	f := cloudagent.ProofFreshness{SnapshotHash: "abc", ObtainedAt: ProbeStamp()}
	now, err := time.Parse(time.RFC3339, ProbeStamp())
	if err != nil {
		t.Fatalf("ProbeStamp does not emit RFC3339: %v", err)
	}
	standing, why := f.Evaluate("abc", now, 0)
	if standing != cloudagent.StandingCurrent {
		t.Fatalf("a freshly stamped proof reads as %q (%s) — the layout does not round-trip", standing, why)
	}
}

// THE ROUTING TEST, and the reason it drives the HANDLER rather than proberOrNil directly.
//
// A previous campaign found exactly this shape: direct-call tests passed with the routing removed,
// which reproduces the built-but-not-wired gap INSIDE the tests written to prove wiring. proberOrNil
// returning a prober proves nothing if nothing puts it on the agent's Context.
//
// probe_coverage is the observable: ProbeCoverage() returns nil when no prober is configured — so a
// run with zero probes renders as "we did not look" — and non-nil the moment one is, carrying the
// prober's own Coverage() line. Its presence in the response is therefore proof the Prober reached
// the agent.
func TestCloudInvestigate_ThePlatformPutsTheProberOnTheAgentContext(t *testing.T) {
	st := store.NewMemory()
	withAWSConnection(t, st, "t1", platform.ConnActive)

	h := NewHandler(Deps{
		Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		AgentLLM:    fakeCloudLLM{},
		CloudProber: func(platform.Connection) cloudagent.ExploitProber { return recordingProber{} },
	})
	rec := do(h, "POST", "/v1/cloud/investigate", "t1", `{"inventory":{"account_id":"1","provider":"aws"}}`)
	if rec.Code != 200 {
		t.Fatalf("run failed (%d): %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "probe_coverage") {
		t.Fatal("the response carries no probe_coverage, so the prober never reached the agent's " +
			"Context — every path stays config-possible and P1 is inert in the product")
	}
}

// The mirror: with no prober wired, probe_coverage must be ABSENT rather than a zeroed tally. A tally
// of 0 tested / 0 allowed reads as an account that was checked and came back clean.
func TestCloudInvestigate_NoProberOmitsCoverageRatherThanZeroingIt(t *testing.T) {
	st := store.NewMemory()
	withAWSConnection(t, st, "t1", platform.ConnActive)

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		AgentLLM: fakeCloudLLM{}}) // no CloudProber
	rec := do(h, "POST", "/v1/cloud/investigate", "t1", `{"inventory":{"account_id":"1","provider":"aws"}}`)
	if rec.Code != 200 {
		t.Fatalf("run failed (%d): %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "probe_coverage") {
		t.Fatal("a run that asked the provider nothing reported probe coverage — a zeroed tally reads " +
			"as an account that was checked and came back clean")
	}
}

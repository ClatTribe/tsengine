package platformapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// END TO END: a leaked-key finding from the CODE surface becomes a stored, enriched cross-surface
// finding a customer can actually see — the whole point of composing the graph in the platform.
func TestEstate_DetectionReachesTheCustomer(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()

	// gitleaks-shaped finding: the key id lives in the finding's OWN text, which is what
	// FromLeakedSecrets extracts (never the rule name).
	_ = st.PutFinding(ctx, "t1", types.Finding{
		ID: "f-leak", RuleID: "gitleaks::aws-access-key", Tool: "gitleaks",
		Severity: types.SeverityHigh, Endpoint: "repo/app.py",
		Title: "AWS access key committed", Description: "AKIAIOSFODNN7EXAMPLE found in app.py",
	})

	// The graph is composable and reports honestly that one surface cannot be joined.
	g := do(h, "GET", "/v1/estate", "t1", "")
	if g.Code != 200 {
		t.Fatalf("GET /v1/estate: %d %s", g.Code, g.Body.String())
	}
	if !strings.Contains(g.Body.String(), `"joinable":false`) {
		t.Errorf("with only the code surface present, joinable must be false: %s", g.Body.String())
	}

	// Detection runs and persists through the normal pipeline.
	rec := do(h, "POST", "/v1/estate/detect", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("POST /v1/estate/detect: %d %s", rec.Code, rec.Body.String())
	}

	// A code-only estate has nothing to JOIN, so it must detect nothing — the honest answer, and
	// the guard against this endpoint inventing cross-surface drama from one surface.
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	for _, f := range stored {
		if strings.HasPrefix(f.RuleID, "estate::") {
			t.Errorf("a single-surface estate produced a cross-surface finding %q", f.RuleID)
		}
	}
}

// Tenant isolation: one tenant's estate must never be composed from another's findings.
func TestEstate_IsTenantIsolated(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()
	_ = st.PutFinding(ctx, "t2", types.Finding{
		ID: "f-other", Tool: "gitleaks", Endpoint: "other/app.py",
		Description: "AKIAIOSFODNN7EXAMPLE found", Severity: types.SeverityHigh,
	})
	body := do(h, "GET", "/v1/estate", "t1", "").Body.String()
	if strings.Contains(body, "other/app.py") || strings.Contains(body, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("t1's estate leaked t2's data: %s", body)
	}
	if !strings.Contains(body, `"node_count":0`) {
		t.Errorf("a tenant with nothing of its own must compose an empty graph, got %s", body)
	}
}

// THE INGEST PATH: connecting a cloud account must AUTOMATICALLY surface the cross-surface path,
// with no separate /v1/estate/detect call. That is the wedge's actual promise — "connect code and
// cloud and the path appears" — and it is a different code path from the explicit detect endpoint,
// so it needs its own proof. Wiring that merely does not crash is not wiring that works.
func TestEstate_CloudInventoryIngestSurfacesTheCrossSurfacePath(t *testing.T) {
	st := store.NewMemory()
	snaps := cloudsnap.NewMemStore()
	h := NewHandler(Deps{Store: st, CloudSnapshots: snaps, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()

	// The CODE surface, already known: a key committed to the repo.
	_ = st.PutFinding(ctx, "t1", types.Finding{
		ID: "f-leak", RuleID: "gitleaks::aws-access-key", Tool: "gitleaks",
		Severity: types.SeverityHigh, Endpoint: "repo/deploy.py",
		Title: "AWS access key committed", Description: "AKIAIOSFODNN7EXAMPLE found in deploy.py",
	})

	// Now the CLOUD surface arrives. Note what the account itself does NOT contain: nothing
	// exposes deploy-role. A cloud scanner alone finds no way in — correctly.
	// The account names the user that key belongs to, and what that user can read. Note what it
	// does NOT contain: nothing exposes this user to the internet. A cloud scanner alone finds no
	// way in, correctly — the way in is the key sitting in the repo.
	body := `{
		"account_id": "111122223333",
		"users": [{"arn":"arn:aws:iam::111122223333:user/deploy","name":"deploy",
			"access_key_ids":["AKIAIOSFODNN7EXAMPLE"]}],
		"buckets": [{"name":"customer-pii","sensitive":true}],
		"grants": [{"principal":"arn:aws:iam::111122223333:user/deploy",
			"resource":"arn:aws:s3:::customer-pii"}]
	}`
	rec := do(h, "POST", "/v1/cloud/inventory", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("POST /v1/cloud/inventory: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "cross_surface_detected") {
		t.Errorf("the ingest response does not report cross-surface detection at all: %s", rec.Body.String())
	}

	// Both surfaces are present now, so the graph must say it is joinable — the precondition for
	// any cross-surface claim, asserted separately so a failure here is legible.
	g := do(h, "GET", "/v1/estate", "t1", "")
	if !strings.Contains(g.Body.String(), `"joinable":true`) {
		t.Fatalf("code + cloud are both stored but the estate is not joinable: %s", g.Body.String())
	}

	// The assertion that actually matters. A response field naming detection, and a graph that
	// COULD be joined, are both satisfied by wiring that runs and finds nothing. The customer's
	// outcome is a stored finding.
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	var cross []string
	for _, f := range stored {
		if strings.HasPrefix(f.RuleID, "estate::") {
			cross = append(cross, f.RuleID)
		}
	}
	if len(cross) == 0 {
		t.Fatalf("connecting the cloud account produced NO cross-surface finding — the wedge's promise "+
			"did not happen on the ingest path (%d finding(s) stored)", len(stored))
	}
	t.Logf("ingest produced cross-surface finding(s): %v", cross)
}

// THE WAREHOUSE JOIN: a table inside Snowflake is readable by a GCP service account the cloud
// account also runs a public box as. The warehouse assessment cannot say the grantee is reachable —
// it has no view of cloud IAM — and the cloud graph cannot say what that identity reads inside a
// warehouse, which is not a cloud resource at all. Only the join says both.
//
// The two converge with no matching logic: estategraph.Canonical maps a *.iam.gserviceaccount.com
// address into the shared principal namespace, so the warehouse grantee IS the cloud node.
func TestEstate_WarehouseGranteeJoinsTheCloudIdentity(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, CloudSnapshots: cloudsnap.NewMemStore(),
		Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()

	// The cloud surface: an internet-reachable box running as that service account.
	inv := `{"account_id":"111122223333",
		"instances":[{"id":"i-web","public_ip":true,"service_port":443,
			"security_group_ids":["sg-open"],"role_arn":"etl@proj.iam.gserviceaccount.com"}],
		"security_groups":[{"id":"sg-open","ingress":"[{\"cidr\":\"0.0.0.0/0\",\"from_port\":443,\"to_port\":443,\"proto\":\"tcp\"}]"}]}`
	if rec := do(h, "POST", "/v1/cloud/inventory", "t1", inv); rec.Code != 200 {
		t.Fatalf("cloud inventory: %d %s", rec.Code, rec.Body.String())
	}

	// The warehouse surface: that same identity can read a table holding customer data.
	wh := `{"objects":[{"platform":"snowflake","name":"analytics.customers","type":"table",
		"sensitive":true,
		"grants":[{"grantee":"etl@proj.iam.gserviceaccount.com","privilege":"SELECT"}]}]}`
	rec := do(h, "POST", "/v1/dataplatform/ingest", "t1", wh)
	if rec.Code != 200 {
		t.Fatalf("dataplatform ingest: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Cross int `json:"cross_surface_detected"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Cross == 0 {
		t.Fatalf("a public box runs as the identity that reads the customer table, and no cross-surface "+
			"finding was produced: %s", rec.Body.String())
	}

	// The customer outcome, asserted on the STORED finding rather than a response count — a count is
	// satisfied by anything, and this must be the warehouse join specifically, not a cloud-only path
	// that happened to be found at the same moment.
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	var reachedWarehouse bool
	for _, f := range stored {
		if strings.HasPrefix(f.RuleID, "estate::") &&
			(strings.Contains(f.Endpoint, "analytics.customers") || strings.Contains(f.Description, "analytics.customers")) {
			reachedWarehouse = true
		}
	}
	if !reachedWarehouse {
		t.Fatalf("a cross-surface finding was produced but none of them reaches the warehouse table — " +
			"the join being tested is not the one that fired")
	}
}

// THE LIMITATION, pinned deliberately. Nothing persists a grant snapshot, so the warehouse joins the
// estate only at the moment it is posted; an estate composed later has no warehouse in it. That is a
// real gap, and this test exists so that persisting the snapshot is a deliberate change rather than
// something a future reader assumes already happened.
func TestEstate_WarehouseIsNotInALaterComposedEstate(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, CloudSnapshots: cloudsnap.NewMemStore(),
		Connectors: connector.NewRegistry(), Token: "platform-tok"})

	wh := `{"objects":[{"platform":"snowflake","name":"analytics.customers","type":"table","sensitive":true,
		"grants":[{"grantee":"etl@proj.iam.gserviceaccount.com","privilege":"SELECT"}]}]}`
	if rec := do(h, "POST", "/v1/dataplatform/ingest", "t1", wh); rec.Code != 200 {
		t.Fatalf("dataplatform ingest: %d %s", rec.Code, rec.Body.String())
	}

	g := do(h, "GET", "/v1/estate", "t1", "")
	if strings.Contains(g.Body.String(), "analytics.customers") {
		t.Errorf("the warehouse now survives into a later-composed estate — good, but the caveat in " +
			"composeEstateWith and the roadmap both still say it does not; update them together")
	}
}

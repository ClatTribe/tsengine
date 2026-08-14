package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudhistory"
)

func histReq(t *testing.T, d Deps, tenant, resource string) map[string]any {
	t.Helper()
	u := "/v1/cloud/history"
	if resource != "" {
		u += "?resource=" + resource
	}
	rec := httptest.NewRecorder()
	d.handleCloudHistory(rec, httptest.NewRequest(http.MethodGet, u, nil), tenant)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body
}

func seedTimeline(t *testing.T) Deps {
	t.Helper()
	ctx := context.Background()
	h := cloudhistory.NewMemStore()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, _ = h.Append(ctx, cloudhistory.Digest{TenantID: "t1", CapturedAt: base,
		Resources: map[string]cloudhistory.ResourceState{"bucket-a": {Type: "s3"}}})
	_, _ = h.Append(ctx, cloudhistory.Digest{TenantID: "t1", CapturedAt: base.Add(time.Hour),
		Resources: map[string]cloudhistory.ResourceState{"bucket-a": {Type: "s3", Public: true}}})
	return Deps{CloudHistory: h}
}

// THE POINT: the endpoint answers when a resource changed.
func TestCloudHistory_AnswersWhenAResourceChanged(t *testing.T) {
	body := histReq(t, seedTimeline(t), "t1", "bucket-a")
	raw, _ := json.Marshal(body["changes"])
	if !strings.Contains(string(raw), "internet-facing") {
		t.Errorf("the transition is not reported: %s", raw)
	}
}

// NO HISTORY MUST NOT READ AS "NOTHING CHANGED". That conflation is the whole risk of a timeline
// feature: an empty list looks reassuring and means the opposite.
func TestCloudHistory_EmptyIsNotAnAllClear(t *testing.T) {
	// Not configured at all.
	body := histReq(t, Deps{}, "t1", "")
	note, _ := body["note"].(string)
	if !strings.Contains(strings.ToLower(note), "not a statement that nothing changed") {
		t.Errorf("an unconfigured history returned a note that could be read as an all-clear: %q", note)
	}
	// Configured but empty.
	body = histReq(t, Deps{CloudHistory: cloudhistory.NewMemStore()}, "t1", "")
	note, _ = body["note"].(string)
	if !strings.Contains(strings.ToLower(note), "have not been watching") {
		t.Errorf("an empty timeline must say we have not been watching, got: %q", note)
	}
}

// One capture cannot show change, and the response must say so rather than implying stability.
func TestCloudHistory_SingleCaptureSaysSo(t *testing.T) {
	ctx := context.Background()
	h := cloudhistory.NewMemStore()
	_, _ = h.Append(ctx, cloudhistory.Digest{TenantID: "t1", CapturedAt: time.Now(),
		Resources: map[string]cloudhistory.ResourceState{"a": {Public: true}}})
	note, _ := histReq(t, Deps{CloudHistory: h}, "t1", "")["note"].(string)
	if !strings.Contains(strings.ToLower(note), "nothing to compare") {
		t.Errorf("a single capture should say there is nothing to compare against, got: %q", note)
	}
}

// The between-captures limit must be stated — a change that reverted inside one interval is invisible,
// and a reader who assumes continuous observation would draw a false conclusion.
func TestCloudHistory_StatesTheBetweenCapturesLimit(t *testing.T) {
	note, _ := histReq(t, seedTimeline(t), "t1", "")["note"].(string)
	if !strings.Contains(strings.ToLower(note), "between captures") {
		t.Errorf("the response does not warn that observation is between captures: %q", note)
	}
}

// Tenant isolation (§18.2 inv. 2).
func TestCloudHistory_IsTenantScoped(t *testing.T) {
	d := seedTimeline(t)
	body := histReq(t, d, "other-tenant", "bucket-a")
	raw, _ := json.Marshal(body["changes"])
	if strings.Contains(string(raw), "bucket-a") {
		t.Errorf("ISOLATION: another tenant's history leaked: %s", raw)
	}
}

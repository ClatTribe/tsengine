package platformapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestReviews_CreateListResolve(t *testing.T) {
	h, _ := setup(t)

	rec := do(h, "POST", "/v1/reviews", "t1",
		`{"subject":"finding","subject_id":"f-001","note":"unsure if exploitable","requester":"alice"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var created platform.ReviewRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" || created.Status != platform.ReviewOpen {
		t.Fatalf("created review malformed: %+v", created)
	}

	rec = do(h, "GET", "/v1/reviews", "t1", "")
	var list []platform.ReviewRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].SubjectID != "f-001" {
		t.Fatalf("list: want the created review, got %+v", list)
	}

	rec = do(h, "POST", "/v1/reviews/"+created.ID+"/resolve", "t1",
		`{"resolution":"confirmed exploitable, approve the fix","reviewer":"sec-eng"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resolved platform.ReviewRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &resolved)
	if resolved.Status != platform.ReviewResolved || resolved.Reviewer != "sec-eng" {
		t.Errorf("resolve didn't take: %+v", resolved)
	}
}

func TestReviews_Validation(t *testing.T) {
	h, _ := setup(t)
	if rec := do(h, "POST", "/v1/reviews", "t1", `{"subject":"nonsense","subject_id":"x"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad subject should be 400, got %d", rec.Code)
	}
	if rec := do(h, "POST", "/v1/reviews", "t1", `{"subject":"finding"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("missing subject_id should be 400, got %d", rec.Code)
	}
	if rec := do(h, "POST", "/v1/reviews/nope/resolve", "t1", `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("resolve missing review should be 404, got %d", rec.Code)
	}
}

func TestReviews_TenantIsolation(t *testing.T) {
	h, _ := setup(t)
	_ = do(h, "POST", "/v1/reviews", "t1", `{"subject":"finding","subject_id":"f-1"}`)
	rec := do(h, "GET", "/v1/reviews", "t2", "")
	var list []platform.ReviewRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Errorf("ISOLATION: t2 must see no reviews, got %d", len(list))
	}
}

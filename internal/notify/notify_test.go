package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestSlack_PostsApprovalWithButtons(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewSlack(srv.URL)
	s.HTTP = srv.Client()
	a := platform.Action{ID: "act-9", TenantID: "t1", Kind: platform.ActApplyConfig, Tier: 2, FindingID: "f-3", Title: "Public S3"}
	if err := s.ApprovalNeeded(context.Background(), a); err != nil {
		t.Fatal(err)
	}

	// the message must carry both buttons, with value = tenant:actionID so the
	// interactive callback can resolve + decide it
	blocks, _ := got["blocks"].([]any)
	if len(blocks) < 2 {
		t.Fatalf("want section+actions blocks, got %d", len(blocks))
	}
	elems := blocks[1].(map[string]any)["elements"].([]any)
	if len(elems) != 2 {
		t.Fatalf("want approve+reject buttons, got %d", len(elems))
	}
	approve := elems[0].(map[string]any)
	if approve["action_id"] != "approve" || approve["value"] != "t1:act-9" {
		t.Errorf("approve button wrong: %+v", approve)
	}
	if elems[1].(map[string]any)["action_id"] != "reject" {
		t.Errorf("second button should be reject: %+v", elems[1])
	}
}

func TestSlack_NilAndEmptyAreNoops(t *testing.T) {
	var s *Slack
	if err := s.ApprovalNeeded(context.Background(), platform.Action{}); err != nil {
		t.Errorf("nil Slack should be a no-op, got %v", err)
	}
	if err := (&Slack{}).ApprovalNeeded(context.Background(), platform.Action{}); err != nil {
		t.Errorf("empty-webhook Slack should be a no-op, got %v", err)
	}
}

func TestSlack_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := NewSlack(srv.URL)
	s.HTTP = srv.Client()
	if err := s.ApprovalNeeded(context.Background(), platform.Action{ID: "x"}); err == nil {
		t.Error("a 500 from Slack should be an error")
	}
}

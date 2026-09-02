package grcexport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestRecords_MapStatesDeterministically(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	states := []platform.ControlState{
		{Framework: "soc2", ControlID: "CC6.6", State: platform.ControlGap, EvidenceRefs: []string{"f1", "f2"}, UpdatedAt: now},
		{Framework: "soc2", ControlID: "CC6.1", State: platform.ControlMet, UpdatedAt: now},
		{Framework: "", ControlID: "x", State: platform.ControlMet}, // unattributable → not a row
	}
	rs := Records(states, "https://app.example/", "Northwind Security")
	if len(rs) != 2 || rs[0].ID != "soc2-CC6.1" || rs[1].ID != "soc2-CC6.6" {
		t.Fatalf("want two rows sorted by id, got %+v", rs)
	}
	gap := rs[1]
	if gap.Met || gap.State != "gap" || gap.EvidenceCount != 2 || gap.EvidenceURL != "https://app.example/compliance/soc2" || gap.AssessedAt != "2026-09-02T10:00:00Z" || gap.Source != "Northwind Security" {
		t.Fatalf("gap row wrong: %+v", gap)
	}
	if !rs[0].Met || rs[0].State != "met" {
		t.Fatalf("met row wrong: %+v", rs[0])
	}
	// the schema declares every field a record carries
	var probe map[string]any
	b, _ := json.Marshal(rs[0])
	_ = json.Unmarshal(b, &probe)
	props := Schema["properties"].(map[string]any)
	for k := range probe {
		if _, ok := props[k]; !ok {
			t.Errorf("record field %q is not in the schema Drata is told about", k)
		}
	}
}

// fakeDrata records the calls a push makes and answers as Drata's recipe documents.
type fakeDrata struct {
	calls []string
	auth  string
	rows  int
}

func (f *fakeDrata) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "POST" && r.URL.Path == "/public/v2/custom-connections":
			var b map[string]any
			_ = json.Unmarshal(body, &b)
			if b["displayNameKey"] != DisplayNameKey || b["schema"] == nil {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`{"id":42,"customResources":[{"id":7}]}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/actions"):
			if !strings.Contains(string(body), `"complete"`) {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/sessions/"):
			var b struct {
				Data []Record `json:"data"`
			}
			_ = json.Unmarshal(body, &b)
			f.rows += len(b.Data)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(404)
		}
	})
}

func TestClient_EnsureConnectionThenPushAsOneCompletedSession(t *testing.T) {
	f := &fakeDrata{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, APIKey: "k"}
	ctx := context.Background()

	conn, err := c.EnsureConnection(ctx, Connection{}, "TensorShield control posture", 1)
	if err != nil || conn.ConnectionID != 42 || conn.ResourceID != 7 {
		t.Fatalf("ensure: %+v %v", conn, err)
	}
	if f.auth != "Bearer k" {
		t.Fatalf("auth header = %q", f.auth)
	}
	// already configured → no create call
	if again, err := c.EnsureConnection(ctx, conn, "x", 1); err != nil || again != conn || len(f.calls) != 1 {
		t.Fatalf("a configured connection must not be recreated: %+v %v calls=%v", again, err, f.calls)
	}

	rs := Records([]platform.ControlState{{Framework: "soc2", ControlID: "CC6.1", State: platform.ControlMet}}, "", "TensorShield")
	res, err := c.Push(ctx, conn, rs, time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC))
	if err != nil || !res.Replaced || res.Records != 1 || res.SessionID != "ts-20260902-100000" || f.rows != 1 {
		t.Fatalf("push: %+v %v rows=%d", res, err, f.rows)
	}
	if !strings.HasSuffix(f.calls[len(f.calls)-1], "/sessions/ts-20260902-100000/actions") {
		t.Fatalf("the session must be completed last, calls=%v", f.calls)
	}

	// an empty set is refused: completing it would erase the previous batch
	if _, err := c.Push(ctx, conn, nil, time.Now()); err == nil {
		t.Fatal("empty push must be refused")
	}
	// no key → no call
	if _, err := (&Client{BaseURL: srv.URL}).Push(ctx, conn, rs, time.Now()); err == nil {
		t.Fatal("a client without a key must refuse")
	}
}

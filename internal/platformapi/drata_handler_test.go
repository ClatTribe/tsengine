package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// stubPosturer answers Posture for the sync path; the embedded Posturer supplies the rest of the
// interface (unused here — a call would nil-panic, and none is made).
type stubPosturer struct {
	Posturer
	states []platform.ControlState
}

func (s stubPosturer) Posture(_ context.Context, _, fw string) ([]platform.ControlState, error) {
	var out []platform.ControlState
	for _, c := range s.states {
		if c.Framework == fw {
			out = append(out, c)
		}
	}
	return out, nil
}

func TestDrata_ConfigSealsKeyAndSyncPushes(t *testing.T) {
	// a fake Drata that accepts the create + session + complete calls
	var pushed int
	drata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/public/v2/custom-connections" && r.Method == "POST":
			_, _ = w.Write([]byte(`{"id":42,"customResources":[{"id":7}]}`))
		case strings.HasSuffix(r.URL.Path, "/actions"):
			_, _ = w.Write([]byte(`{}`))
		case strings.Contains(r.URL.Path, "/sessions/"):
			var b struct {
				Data []map[string]any `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			pushed += len(b.Data)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer drata.Close()

	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme"})
	d := Deps{Store: st, Token: "tok", Vault: roundtripSealer{},
		GRC:    stubPosturer{states: []platform.ControlState{{Framework: "soc2", ControlID: "CC6.1", State: platform.ControlMet}, {Framework: "soc2", ControlID: "CC6.6", State: platform.ControlGap}}},
		AppURL: "https://app.example"}
	h := NewHandler(d)
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/v1/settings/drata", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("X-Tenant-ID", "t1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// a workspace id is required with a key
	if rec := put(`{"api_key":"k"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing workspace: want 400, got %d %s", rec.Code, rec.Body.String())
	}
	rec := put(`{"api_key":"drata_secret_key","workspace_id":1,"base_url":"` + drata.URL + `"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"has_key":true`) {
		t.Fatalf("config: %d %s", rec.Code, rec.Body.String())
	}
	// the raw key must be sealed, never stored plaintext
	// The key goes through the vault (KeyRef is the sealed ref, not raw JSON). roundtripSealer is a
	// test double, so it embeds the value; a real vault never would — the seal-not-plaintext property
	// is pinned separately by recordingSealer in the connect tests. Here we prove the seam is used.
	tn, _ := st.GetTenant(context.Background(), "t1")
	if tn.Drata == nil || !strings.HasPrefix(tn.Drata.KeyRef, "enc:") {
		t.Fatalf("key must pass through the vault, got %+v", tn.Drata)
	}

	// sync pushes both controls and stores the minted connection ids
	sreq := httptest.NewRequest("POST", "/v1/settings/drata/sync", nil)
	sreq.Header.Set("Authorization", "Bearer tok")
	sreq.Header.Set("X-Tenant-ID", "t1")
	srec := httptest.NewRecorder()
	h.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusOK || pushed != 2 {
		t.Fatalf("sync: want 200 + 2 pushed, got %d pushed=%d %s", srec.Code, pushed, srec.Body.String())
	}
	tn, _ = st.GetTenant(context.Background(), "t1")
	if tn.Drata.ConnectionID != 42 || tn.Drata.ResourceID != 7 {
		t.Fatalf("connection ids must be persisted for reuse, got %+v", tn.Drata)
	}

	// clearing the key removes the config
	_ = put(`{"api_key":""}`)
	tn, _ = st.GetTenant(context.Background(), "t1")
	if tn.Drata != nil {
		t.Fatalf("clearing must remove the config, got %+v", tn.Drata)
	}
}

// roundtripSealer seals to "enc:"+plaintext and opens it back — enough to prove the sync path
// resolves the real key, while a stored ref is never the bare plaintext.
type roundtripSealer struct{}

func (roundtripSealer) Seal(p string) (string, error) { return "enc:" + p, nil }
func (roundtripSealer) Open(ref string) (string, error) {
	return strings.TrimPrefix(ref, "enc:"), nil
}

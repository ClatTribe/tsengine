package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Silence is not agreement. A tenant that has never been asked, and a store that cannot
// be read, must both come back NOT consented — a read error becoming a yes is the one
// failure here that nobody would notice.
func TestResolveTrainingConsent_DefaultsToNo(t *testing.T) {
	var none Deps
	if none.resolveTrainingConsent(context.Background(), "t1").Consented {
		t.Error("no store must not read as consent")
	}
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	if (Deps{Store: st}).resolveTrainingConsent(ctx, "t1").Consented {
		t.Error("an unconfigured tenant must not read as consent")
	}
}

func TestApplyTrainingConsent_StampsBeforeTheRun(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1", Training: &platform.TrainingConsent{
		Consented: true, By: "owner@acme.test", At: time.Unix(100, 0).UTC(), Statement: "agreed text",
	}}); err != nil {
		t.Fatal(err)
	}
	d := Deps{Store: st}
	e := ledger.NewEpisode(&ledger.Ledger{AgentKind: "cloudagent"}, nil)
	d.applyTrainingConsent(ctx, "t1", e)
	if !e.Trainable() {
		t.Fatal("a consented tenant's episode must be trainable")
	}
	if e.Training.Statement != "agreed text" {
		t.Errorf("the stored statement must ride verbatim, got %q", e.Training.Statement)
	}
	if e.Training.ConsentedBy != "owner@acme.test" {
		t.Errorf("ConsentedBy = %q", e.Training.ConsentedBy)
	}
}

// The stamp must be refused once the episode has closed, or consent becomes something
// that can be applied to data already collected. Guarding it here as well as in
// pkg/ledger, because this is the caller that could get the ordering wrong.
func TestApplyTrainingConsent_CannotReachAClosedEpisode(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1", Training: &platform.TrainingConsent{
		Consented: true, By: "owner@acme.test", At: time.Unix(100, 0).UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	e := ledger.NewEpisode(&ledger.Ledger{AgentKind: "cloudagent"},
		&ledger.SecurityState{Scope: "cloud:t1"})
	if err := e.Close(&ledger.SecurityState{Scope: "cloud:t1"}); err != nil {
		t.Fatal(err)
	}
	(Deps{Store: st}).applyTrainingConsent(ctx, "t1", e)
	if e.Trainable() {
		t.Error("an episode that already closed must not become trainable retroactively")
	}
}

// Declining is a recorded act, not an empty field. Without who and when there is no way
// to tell a tenant that said no from one nobody asked.
func TestPutTrainingSettings_WithdrawalIsRecorded(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(Deps{Store: st, Token: "platform-tok"})
	if rec := putJSON(h, "/v1/settings/training", `{"consented":true,"by":"owner@acme.test"}`); rec.Code != 200 {
		t.Fatalf("consent: status %d body %s", rec.Code, rec.Body)
	}
	if rec := putJSON(h, "/v1/settings/training", `{"consented":false,"by":"owner@acme.test"}`); rec.Code != 200 {
		t.Fatalf("withdrawal: status %d body %s", rec.Code, rec.Body)
	}
	got, err := st.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Training == nil || got.Training.Consented {
		t.Fatalf("withdrawal must persist as a recorded no, got %+v", got.Training)
	}
	if got.Training.By == "" || got.Training.At.IsZero() {
		t.Errorf("a withdrawal that erases itself is indistinguishable from never being asked: %+v", got.Training)
	}
}

// An unattributed consent is not one anybody can stand behind later.
func TestPutTrainingSettings_ConsentNeedsANamedHuman(t *testing.T) {
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(Deps{Store: st, Token: "platform-tok"})
	if rec := putJSON(h, "/v1/settings/training", `{"consented":true}`); rec.Code != 400 {
		t.Errorf("status %d body %s; want 400 for an unattributed consent", rec.Code, rec.Body)
	}
}

func putJSON(h http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("PUT", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer platform-tok")
	req.Header.Set("X-Tenant-ID", "t1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDomainResolvesRejectsNonExistent is the regression guard for a §10 grounding violation on
// the public lead magnet: a domain that was never registered used to be scored (grade D, "you'd
// fail 3 of 3 checks", "No DMARC record — anyone can spoof your domain") because every DNS record
// is trivially absent for a domain that does not exist. FetchDomain treats a lookup miss as the
// finding, which is right for a real domain and wrong for a fictional one.
//
// .invalid is reserved by RFC 2606 and is guaranteed never to resolve, so this is stable rather
// than dependent on whoever happens to own a test domain today.
func TestDomainResolvesRejectsNonExistent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if domainResolves(ctx, "this-domain-does-not-exist-xyz123.invalid") {
		t.Error("a .invalid domain reported as resolving — the guard would let a fictional domain be scored")
	}
}

// TestPublicAssessRefusesNonExistentDomain pins the user-visible half: the endpoint must refuse
// rather than invent a scorecard. A founder who mistypes their domain is the case that matters —
// being shown a fabricated failing grade by the tool whose entire pitch is that its findings are
// real is worse than being shown nothing.
func TestPublicAssessRefusesNonExistentDomain(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/assess?domain=this-domain-does-not-exist-xyz123.invalid", nil)
	r.RemoteAddr = "203.0.113.7:1234" // distinct IP: publicAssessLimiter is package-level state
	w := httptest.NewRecorder()

	Deps{}.handlePublicAssess(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("non-existent domain → %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "resolve") {
		t.Errorf("error should say the domain doesn't resolve, got: %s", w.Body.String())
	}
	// The point of the guard: no scorecard for a domain that isn't there.
	for _, leaked := range []string{"grade", "DMARC", "questionnaire"} {
		if strings.Contains(w.Body.String(), leaked) {
			t.Errorf("response leaked %q for a non-existent domain: %s", leaked, w.Body.String())
		}
	}
}

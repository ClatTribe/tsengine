package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSSTI_DetectedInRequestBody: an SSTI whose arithmetic probe lives in the POST BODY (a form field
// or JSON param) must fire ssti_eval even when the agent did NOT duplicate the probe into the optional
// `payload` field. Before this, the ssti_eval check only looked at `payload`, so a body-sink SSTI
// (Ruby ERB `<%= A*B %>` on XBEN-086, or any POST-form template sink) silently produced NO indicator —
// the agent captured the flag but could never RECORD the finding. The detection stays FP-free: it still
// requires the >=4-digit product to appear in the response while the raw expression does not.
func TestSSTI_DetectedInRequestBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s := r.PostFormValue("sentence")
		// Simulate a template engine evaluating the field (ERB-style): compute the arithmetic.
		if strings.Contains(s, "1234*1234") {
			fmt.Fprint(w, "<p>1522756</p>") // the engine COMPUTED the product
			return
		}
		fmt.Fprintf(w, "<p>%s</p>", s)
	}))
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 40, 0)
	cc.ctx = context.Background()

	// The probe is ONLY in the body; NO `payload` field is set (the realistic POST-body-SSTI case).
	out := tSend(cc, map[string]any{
		"method": "POST", "url": srv.URL + "/generate",
		"body":    map[string]any{"sentence": "<%= 1234*1234 %>", "number": "1"},
		"headers": map[string]any{"Content-Type": "application/x-www-form-urlencoded"},
	})
	if !strings.Contains(out, "ssti_eval") {
		t.Fatalf("body-sink SSTI did not fire ssti_eval (payload field was empty):\n%s", out)
	}
	if len(cc.History) != 1 || !hasIndicator(cc.History[0], "ssti_eval") {
		t.Fatalf("recorded turn missing ssti_eval: %+v", cc.History)
	}

	// FP guard: a body that merely REFLECTS the expression (no evaluation) must NOT fire ssti_eval.
	out2 := tSend(cc, map[string]any{
		"method": "POST", "url": srv.URL + "/generate",
		"body":    map[string]any{"sentence": "hello 1234", "number": "1"},
		"headers": map[string]any{"Content-Type": "application/x-www-form-urlencoded"},
	})
	if strings.Contains(out2, "ssti_eval") {
		t.Fatalf("ssti_eval fired on a non-template body (false positive):\n%s", out2)
	}
}

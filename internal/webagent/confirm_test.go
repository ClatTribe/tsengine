package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestConfirmExploit_RefiresPostBody: confirm_exploit must re-fire a POST-body injection WITH its body
// (and a parseable Content-Type). The proving payload for SSTI/SQLi/cmdi often lives in the POST body,
// not the URL — the Turn records it (turn.Body), but tConfirm re-fired with an empty body + nil headers,
// so the server never received the payload, the indicator "failed" to reproduce, and confirm_exploit
// told the agent to DROP a real verified finding. Here the server evaluates the SSTI probe ONLY when it
// arrives in the POST body, so a body-dropping re-fire cannot reproduce it.
func TestConfirmExploit_RefiresPostBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm() // only parses the body when Content-Type is application/x-www-form-urlencoded
		if strings.Contains(r.PostFormValue("name"), "{{1337*1337}}") {
			fmt.Fprint(w, "<p>Hello 1787569!</p>") // the engine evaluated the product
			return
		}
		fmt.Fprint(w, "<p>Hello</p>") // no payload reached the server → no product
	}))
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 40, 0)
	cc.ctx = context.Background()
	cc.History = []Turn{{
		ID: "t-001", Method: "POST", URL: srv.URL + "/render",
		Body: "name=" + url.QueryEscape("{{1337*1337}}"), Payload: "{{1337*1337}}",
		Indicators: []string{"ssti_eval"},
	}}
	cc.Findings = []Finding{{ID: "f-001", Class: "ssti", Evidence: []string{"t-001"}}}

	out := tConfirm(cc, map[string]any{"finding_id": "f-001"})
	if !strings.Contains(out, "VERIFIED") {
		t.Fatalf("confirm_exploit did not reproduce a POST-body SSTI (the re-fire dropped the body):\n%s", out)
	}
	if !cc.Findings[0].Verified {
		t.Errorf("finding was not marked Verified after a reproducing re-fire")
	}
}

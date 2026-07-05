package webagent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestConfirmExploit_RefiresMultipartUpload: confirm_exploit must re-fire an UPLOAD-based proof with its
// exact multipart body + boundary Content-Type. The proving request for an XXE-via-SVG-upload (XBEN-077)
// or a file-upload RCE is multipart/form-data, but the Turn stores only a display-truncated body (512B)
// and NO Content-Type, so tConfirm re-fired a bare/guessed request → the server 422'd → a REAL finding
// was reported "not reproduced / likely flaky" and the agent told to drop it. The engine now remembers
// the exact sent request per turn so an upload finding can reach Verified. The server here reflects the
// uploaded file's content ONLY when it receives a well-formed multipart upload (as the real app parses
// the SVG's external entity), so a body-dropping or wrong-Content-Type re-fire cannot reproduce it.
func TestConfirmExploit_RefiresMultipartUpload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, _, err := r.FormFile("image") // only succeeds on a real multipart/form-data body
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		defer f.Close()
		buf := make([]byte, 4096)
		n, _ := f.Read(buf)
		// Simulate the app parsing the uploaded SVG's external entity and reflecting the file content.
		if strings.Contains(string(buf[:n]), "SYSTEM") {
			_, _ = w.Write([]byte("Current Image: root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		_, _ = w.Write([]byte("Current Image: (empty)"))
	}))
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 40, 0)
	cc.ctx = context.Background()

	// Drive a REAL upload through tSend so the multipart body + boundary CT are built, sent, the turn
	// recorded, and the exact request remembered — exactly the live path.
	svg := "<?xml version='1.0'?><!DOCTYPE svg [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>" +
		"<svg xmlns='http://www.w3.org/2000/svg'><text>&xxe;</text></svg>"
	out := tSend(cc, map[string]any{
		"method": "POST", "url": srv.URL + "/",
		"upload": map[string]any{"field": "image", "filename": "p.svg", "content": svg, "content_type": "image/svg+xml"},
		"fields": map[string]any{"name": "a"},
	})
	if !hasIndicatorName(out, "file_disclosure") {
		t.Fatalf("upload send did not surface file_disclosure (server should reflect passwd content): %s", out)
	}
	if len(cc.History) != 1 {
		t.Fatalf("expected 1 recorded turn, got %d", len(cc.History))
	}
	turnID := cc.History[0].ID

	rec := tRecord(cc, map[string]any{
		"route": srv.URL + "/", "class": "xxe", "evidence": []any{turnID},
		"severity": "high", "rationale": "SVG upload parsed with external entities → file disclosure",
	})
	if strings.Contains(rec, "REJECTED") {
		t.Fatalf("xxe finding rejected despite a file_disclosure turn: %s", rec)
	}

	cout := tConfirm(cc, map[string]any{"finding_id": cc.Findings[0].ID})
	if !strings.Contains(cout, "VERIFIED") {
		t.Fatalf("confirm_exploit did not re-fire the multipart upload (lost the body/Content-Type):\n%s", cout)
	}
	if !cc.Findings[0].Verified {
		t.Errorf("upload finding not marked Verified after a reproducing re-fire")
	}
}

// hasIndicatorName reports whether a send_request observation string names a given indicator.
func hasIndicatorName(observation, name string) bool {
	return strings.Contains(observation, name)
}

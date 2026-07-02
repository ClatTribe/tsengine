package webagent

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
)

// upload.go adds multipart/form-data (file upload) support to send_request. Hand-crafting a multipart
// body (exact CRLFs, a matching boundary, per-part headers) is error-prone even for a capable model, so
// the agent could not reliably exploit an arbitrary-file-upload at all. With an `upload` arg, tSend
// builds a correct body via the stdlib multipart writer — the agent just names the field/filename/
// content (+ any extra form fields). General web-pentest plumbing, not tied to any target.

// buildUpload constructs a multipart/form-data body when args carries an `upload` object; returns
// (body, contentType, true, nil). Shape: upload={field, filename, content, content_type?} plus optional
// fields={name:value,...} for the other form inputs. Returns ok=false when there is no upload.
func buildUpload(args map[string]any) (body, contentType string, ok bool, err error) {
	up, isUp := args["upload"].(map[string]any)
	if !isUp {
		return "", "", false, nil
	}
	field := strOr(up["field"], "file")
	filename := strOr(up["filename"], "upload.txt")
	content := strOr(up["content"], "")
	ctype := strOr(up["content_type"], "")

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	// any accompanying plain form fields (name, email, csrf, submit, …)
	if fields, ok := args["fields"].(map[string]any); ok {
		for k, v := range fields {
			if s, ok := v.(string); ok {
				_ = w.WriteField(k, s)
			}
		}
	}
	var fw io.Writer
	if ctype != "" { // caller wants a specific part Content-Type (e.g. image/svg+xml for an XXE SVG)
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, field, filename))
		h.Set("Content-Type", ctype)
		fw, err = w.CreatePart(h)
	} else {
		fw, err = w.CreateFormFile(field, filename)
	}
	if err != nil {
		return "", "", false, err
	}
	if _, err = io.WriteString(fw, content); err != nil {
		return "", "", false, err
	}
	if err = w.Close(); err != nil {
		return "", "", false, err
	}
	return buf.String(), w.FormDataContentType(), true, nil
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

package webagent

import "testing"

// TestSSRFMetadata_GroundsInBand: an IMDS credential response reflected in-band sets ssrf_metadata; a
// benign response does not (FP-free, like file_disclosure).
func TestSSRFMetadata_GroundsInBand(t *testing.T) {
	// AWS IMDS security-credentials response (the SSRF→metadata credential-theft vector)
	imds := `{"Code":"Success","LastUpdated":"2026-01-01T00:00:00Z","Type":"AWS-HMAC","AccessKeyId":"ASIAEXAMPLE12345","SecretAccessKey":"x","Token":"y","Expiration":"2026-01-01T06:00:00Z"}`
	if !has(indicators("", "", &Resp{Status: 200, Body: imds}), "ssrf_metadata") {
		t.Error("an in-band IMDS credential response must set ssrf_metadata")
	}
	// STS temp key alone (ASIA prefix) is metadata-sourced → grounds
	if !has(indicators("", "", &Resp{Status: 200, Body: `{"AccessKeyId":"ASIAABCDEF1234567"}`}), "ssrf_metadata") {
		t.Error("an ASIA temp key in the response must set ssrf_metadata")
	}
	// benign responses must NOT false-positive
	for _, body := range []string{
		`{"user":"alice","role":"admin"}`,
		`{"AccessKeyId":"AKIAPERMANENT123"}`, // a permanent AKIA key echoed is NOT the metadata cred structure
		`<html><body>welcome</body></html>`,
		`{"Type":"user","name":"bob"}`,
	} {
		if has(indicators("", "", &Resp{Status: 200, Body: body}), "ssrf_metadata") {
			t.Errorf("benign response must not set ssrf_metadata: %q", body)
		}
	}
}

// TestSSRF_IsGroundedByMetadataOrOOB: the ssrf class now accepts either the OOB callback (blind) or the
// in-band metadata fingerprint.
func TestSSRF_IsGroundedByMetadataOrOOB(t *testing.T) {
	for _, class := range []string{"ssrf", "blind_ssrf", "server_side_request_forgery"} {
		ind := requiredIndicator[class]
		if !contains(ind, "oob_interaction") || !contains(ind, "ssrf_metadata") {
			t.Errorf("class %q must accept both oob_interaction and ssrf_metadata, got %v", class, ind)
		}
	}
}

func has(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

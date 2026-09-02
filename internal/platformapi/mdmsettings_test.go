package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func mdmDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	vault, err := secret.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st, Vault: vault}
}

func putMDM(d Deps, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/v1/settings/mdm", strings.NewReader(body))
	rec := httptest.NewRecorder()
	d.handlePutMDMSettings(rec, req, "ten-1")
	return rec
}

func TestMDMSettings_SealsAndRedacts(t *testing.T) {
	d := mdmDeps(t)
	const tok = "kandji-api-token-XYZ"
	rec := putMDM(d, `{"provider":"kandji","base_url":"https://acme.api.kandji.io/","api_token":"`+tok+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), tok) {
		t.Error("the response must not echo the token")
	}
	if !strings.Contains(rec.Body.String(), `"has_token":true`) || !strings.Contains(rec.Body.String(), `"base_url":"https://acme.api.kandji.io"`) {
		t.Errorf("got %s", rec.Body.String())
	}
	tn, _ := d.Store.GetTenant(context.Background(), "ten-1")
	if tn.MDM == nil || tn.MDM.TokenRef == "" || strings.Contains(tn.MDM.TokenRef, tok) {
		t.Fatalf("token must be stored sealed: %+v", tn.MDM)
	}
	if tn.Redacted().MDM != nil {
		t.Error("Redacted() must drop the MDM block")
	}
	// A second PUT with no token keeps the sealed one.
	before := tn.MDM.TokenRef
	if rec := putMDM(d, `{"provider":"kandji","base_url":"https://acme2.api.kandji.io"}`); rec.Code != http.StatusOK {
		t.Fatalf("re-PUT without token: %d %s", rec.Code, rec.Body.String())
	}
	tn, _ = d.Store.GetTenant(context.Background(), "ten-1")
	if tn.MDM.TokenRef != before || tn.MDM.BaseURL != "https://acme2.api.kandji.io" {
		t.Errorf("blank token must keep the sealed one while the base changes: %+v", tn.MDM)
	}
	// Switching provider DISCARDS the credential (a Kandji token is not a Jamf token).
	if rec := putMDM(d, `{"provider":"jamf","base_url":"https://acme.jamfcloud.com"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("provider switch without a new credential must be refused, got %d %s", rec.Code, rec.Body.String())
	}
	// Clear.
	if rec := putMDM(d, `{"provider":""}`); rec.Code != http.StatusOK {
		t.Fatalf("clear: %d", rec.Code)
	}
	tn, _ = d.Store.GetTenant(context.Background(), "ten-1")
	if tn.MDM != nil {
		t.Error("clear must drop the config")
	}
}

func TestMDMSettings_Refusals(t *testing.T) {
	d := mdmDeps(t)
	for name, body := range map[string]string{
		"unknown provider":        `{"provider":"mosyle","base_url":"https://x.example","api_token":"t"}`,
		"kandji no base":          `{"provider":"kandji","api_token":"t"}`,
		"non-https base":          `{"provider":"kandji","base_url":"http://acme.api.kandji.io","api_token":"t"}`,
		"ssrf metadata ip":        `{"provider":"jamf","base_url":"https://169.254.169.254","api_token":"t"}`,
		"ssrf loopback":           `{"provider":"kandji","base_url":"https://localhost:8443","api_token":"t"}`,
		"kandji no token":         `{"provider":"kandji","base_url":"https://acme.api.kandji.io"}`,
		"jamf half an api client": `{"provider":"jamf","base_url":"https://acme.jamfcloud.com","client_id":"cid"}`,
		"intune nothing to use":   `{"provider":"intune"}`,
	} {
		if rec := putMDM(d, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// Jamf with a full API client is fine and seals the secret.
	rec := putMDM(d, `{"provider":"jamf","base_url":"https://acme.jamfcloud.com","client_id":"cid","client_secret":"shh"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "shh") || !strings.Contains(rec.Body.String(), `"has_client_secret":true`) {
		t.Errorf("jamf api client: %d %s", rec.Code, rec.Body.String())
	}
}

func TestMDMSettings_IntuneMayBorrowTheM365Connection(t *testing.T) {
	d := mdmDeps(t)
	_ = d.Store.PutConnection(context.Background(), platform.Connection{ID: "c-m365", TenantID: "ten-1", Kind: platform.ConnM365, Status: platform.ConnActive, SecretRef: "sealed-graph"})
	rec := putMDM(d, `{"provider":"intune","base_url":"https://attacker.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("intune with an M365 connection needs no token of its own: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"m365_connected":true`) {
		t.Errorf("the page must be told the sync will use the M365 connection: %s", rec.Body.String())
	}
	tn, _ := d.Store.GetTenant(context.Background(), "ten-1")
	if tn.MDM.BaseURL != "" {
		t.Error("a customer-supplied Graph base is not honoured — Graph is a fixed host")
	}
}

// The live sync: a fake Kandji behind MDMHTTP, the config pointed at it directly in the store (the
// PUT screen would refuse a loopback base; the guarded client refuses it at dial time in prod, which
// is why the test injects a plain client). The unencrypted laptop lands as a stored finding, the
// posture source is stamped, and the response says what Kandji cannot report.
func TestSyncDevices_LiveKandjiThroughTheSameIngest(t *testing.T) {
	d := mdmDeps(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kt" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/devices":
			if r.URL.Query().Get("offset") != "0" {
				fmt.Fprint(w, `[]`)
				return
			}
			fmt.Fprint(w, `[{"device_id":"d1","device_name":"mac-alice","platform":"Mac","user":{"email":"alice@acme.io"}},{"device_id":"d2","device_name":"mac-bob","platform":"Mac"}]`)
		case strings.HasSuffix(r.URL.Path, "/d1/details"):
			fmt.Fprint(w, `{"filevault":{"filevault_enabled":false}}`)
		case strings.HasSuffix(r.URL.Path, "/d2/details"):
			fmt.Fprint(w, `{"filevault":{"filevault_enabled":true}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ref, _ := d.Vault.Seal("kt")
	tn, _ := d.Store.GetTenant(context.Background(), "ten-1")
	tn.MDM = &platform.MDMConfig{Provider: platform.MDMKandji, BaseURL: srv.URL, TokenRef: ref}
	_ = d.Store.PutTenant(context.Background(), tn)
	d.MDMHTTP = srv.Client()

	req := httptest.NewRequest(http.MethodPost, "/v1/devices/sync", nil)
	rec := httptest.NewRecorder()
	d.handleSyncDevices(rec, req, "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Provider       string   `json:"provider"`
		Source         string   `json:"source"`
		Devices        int      `json:"devices"`
		IssuesDetected int      `json:"issues_detected"`
		ChecksNotRun   []string `json:"checks_not_run"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Provider != "kandji" || resp.Source != "live" || resp.Devices != 2 || resp.IssuesDetected != 1 {
		t.Fatalf("resp: %+v", resp)
	}
	joined := strings.Join(resp.ChecksNotRun, " | ")
	if !strings.Contains(joined, "Kandji") || !strings.Contains(joined, "screen lock") {
		t.Errorf("the provider's limits must reach checks_not_run: %q", joined)
	}
	stored, _ := d.Store.ListFindings(context.Background(), "ten-1", store.FindingFilter{})
	if len(stored) != 1 || stored[0].RuleID != "deviceposture::disk-unencrypted" || !strings.Contains(stored[0].Title, "mac-alice") {
		t.Errorf("alice's disk must be stored as a finding: %+v", stored)
	}
	tn, _ = d.Store.GetTenant(context.Background(), "ten-1")
	if _, ok := tn.PostureAssessed["deviceposture"]; !ok {
		t.Error("the sync must stamp the posture source")
	}

	// A rejected token is the provider's error, verbatim — never a 200 with zero devices.
	bad, _ := d.Vault.Seal("wrong")
	tn.MDM.TokenRef = bad
	_ = d.Store.PutTenant(context.Background(), tn)
	rec = httptest.NewRecorder()
	d.handleSyncDevices(rec, httptest.NewRequest(http.MethodPost, "/v1/devices/sync", nil), "ten-1")
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "401") {
		t.Errorf("bad token: want 502 carrying the 401, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestSyncDevices_NoSourceIs400(t *testing.T) {
	d := mdmDeps(t)
	rec := httptest.NewRecorder()
	d.handleSyncDevices(rec, httptest.NewRequest(http.MethodPost, "/v1/devices/sync", nil), "ten-1")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("no MDM configured → 400, got %d", rec.Code)
	}
}

package mdm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/deviceposture"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func devByName(t *testing.T, devs []deviceposture.Device, name string) deviceposture.Device {
	t.Helper()
	for _, d := range devs {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("device %q not returned; got %+v", name, devs)
	return deviceposture.Device{}
}

func b(v bool) *bool { return &v }

// --- Kandji ---

func kandjiServer(t *testing.T, details map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kandji-tok" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"detail":"Invalid token."}`)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/devices":
			if r.URL.Query().Get("offset") != "0" {
				fmt.Fprint(w, `[]`)
				return
			}
			fmt.Fprint(w, `[
			  {"device_id":"d1","device_name":"mac-alice","platform":"Mac","os_version":"14.5","last_check_in":"2026-08-30T10:00:00Z","user":{"email":"alice@acme.io"}},
			  {"device_id":"d2","device_name":"mac-bob","platform":"Mac","os_version":"13.1","user":{"email":"bob@acme.io"}},
			  {"device_id":"d3","device_name":"iphone-carol","platform":"iPhone","os_version":"17.4","user":{"email":"carol@acme.io"}},
			  {"device_id":"d4","device_name":"mac-gone","platform":"Mac","is_removed":true}
			]`)
		case strings.HasPrefix(r.URL.Path, "/api/v1/devices/") && strings.HasSuffix(r.URL.Path, "/details"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/devices/"), "/details")
			body, ok := details[id]
			if !ok {
				w.WriteHeader(500)
				return
			}
			fmt.Fprint(w, body)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestKandjiMapsFileVaultAndLeavesUnreportedNil(t *testing.T) {
	srv := kandjiServer(t, map[string]string{
		"d1": `{"general":{"assigned_user":{"email":"alice@acme.io"}},"filevault":{"filevault_enabled":true}}`,
		"d2": `{"general":{},"filevault":{"filevault_enabled":false}}`,
		"d3": `{"general":{"assigned_user":{"email":"carol@acme.io"}}}`, // an iPhone: no FileVault section at all
	})
	defer srv.Close()
	k := &Kandji{BaseURL: srv.URL, Token: "kandji-tok", HTTP: srv.Client()}
	devs, rep, err := k.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Provider != platform.MDMKandji || rep.Devices != 3 {
		t.Fatalf("report: %+v", rep)
	}
	if len(rep.ProviderLimits) == 0 {
		t.Fatal("Kandji cannot report screen lock / firewall / EDR / auto-update per device — the report must say so")
	}
	alice := devByName(t, devs, "mac-alice")
	if alice.DiskEncrypted == nil || !*alice.DiskEncrypted || alice.OS != "macos" || alice.Owner != "alice@acme.io" {
		t.Errorf("alice: %+v", alice)
	}
	bob := devByName(t, devs, "mac-bob")
	if bob.DiskEncrypted == nil || *bob.DiskEncrypted {
		t.Errorf("bob's FileVault is reported OFF and must be a definite false: %+v", bob)
	}
	carol := devByName(t, devs, "iphone-carol")
	if carol.DiskEncrypted != nil {
		t.Errorf("an iPhone has no FileVault section; disk state must be NOT REPORTED (nil), got %v", *carol.DiskEncrypted)
	}
	if carol.OS != "ios" {
		t.Errorf("iPhone platform → ios, got %q", carol.OS)
	}
	for _, d := range devs {
		if d.Name == "mac-gone" {
			t.Error("a removed device must not be assessed")
		}
		if d.ScreenLock != nil || d.FirewallOn != nil || d.EDR != nil || d.AutoUpdate != nil {
			t.Errorf("Kandji never reports these; a non-nil value is a fabrication: %+v", d)
		}
	}
	// The whole contract in one line: a fleet whose only reported setting is FileVault-on
	// produces NO findings. Anything else means a nil was read as false somewhere.
	if fs := deviceposture.Assess([]deviceposture.Device{alice, carol}, deviceposture.Options{}); len(fs) != 0 {
		t.Errorf("unreported settings became findings: %+v", fs)
	}
}

func TestKandjiDetailFailureIsNamedNotSwallowed(t *testing.T) {
	srv := kandjiServer(t, map[string]string{
		"d1": `{"filevault":{"filevault_enabled":true}}`,
		// d2 has no detail → the server 500s
		"d3": `{}`,
	})
	defer srv.Close()
	k := &Kandji{BaseURL: srv.URL, Token: "kandji-tok", HTTP: srv.Client()}
	devs, rep, err := k.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 3 {
		t.Fatalf("a failed detail read keeps the device (with disk unreported): %d", len(devs))
	}
	if len(rep.Unread) != 1 || rep.Unread[0] != "mac-bob" {
		t.Errorf("the device whose detail failed must be NAMED in Unread, got %v", rep.Unread)
	}
	if devByName(t, devs, "mac-bob").DiskEncrypted != nil {
		t.Error("disk state of an unread device must be nil")
	}
}

func TestKandjiDetailCapNamesEveryDeviceBeyondIt(t *testing.T) {
	srv := kandjiServer(t, map[string]string{"d1": `{"filevault":{"filevault_enabled":true}}`})
	defer srv.Close()
	k := &Kandji{BaseURL: srv.URL, Token: "kandji-tok", HTTP: srv.Client(), MaxDetail: 1}
	_, rep, err := k.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Unread) != 2 {
		t.Errorf("two devices sit beyond the cap and both must be named: %v", rep.Unread)
	}
}

func TestKandjiBadTokenIsAnErrorNotAnEmptyFleet(t *testing.T) {
	srv := kandjiServer(t, nil)
	defer srv.Close()
	k := &Kandji{BaseURL: srv.URL, Token: "wrong", HTTP: srv.Client()}
	_, _, err := k.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a rejected token must surface as an error carrying the status, got %v", err)
	}
}

func TestLoginPageWith200IsAnErrorNotAnEmptyFleet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>Sign in</body></html>")
	}))
	defer srv.Close()
	for name, f := range map[string]Fetcher{
		"kandji": &Kandji{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()},
		"jamf":   &Jamf{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()},
		"intune": &Intune{APIBase: srv.URL, Token: "t", HTTP: srv.Client()},
	} {
		if _, _, err := f.Fetch(context.Background()); err == nil {
			t.Errorf("%s: an HTML page served with 200 must be an error, not zero devices", name)
		}
	}
}

// --- Jamf ---

func jamfServer(t *testing.T, wantBearer string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/oauth/token":
			_ = r.ParseForm()
			if r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "csec" || r.Form.Get("grant_type") != "client_credentials" {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"access_token":"minted","expires_in":1799}`)
		case "/api/v1/computers-inventory":
			if r.Header.Get("Authorization") != "Bearer "+wantBearer {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"httpStatus":401,"errors":[{"code":"INVALID_TOKEN"}]}`)
				return
			}
			secs := r.URL.Query()["section"]
			if len(secs) < 5 {
				t.Errorf("inventory must request every posture section, got %v", secs)
			}
			if r.URL.Query().Get("page") != "0" {
				fmt.Fprint(w, `{"totalCount":3,"results":[]}`)
				return
			}
			fmt.Fprint(w, `{"totalCount":3,"results":[
			  {"id":"1","general":{"name":"mbp-dana","lastContactTime":"2026-08-30T09:00:00Z"},"operatingSystem":{"name":"macOS","version":"14.6"},"userAndLocation":{"email":"dana@acme.io"},"diskEncryption":{"bootPartitionEncryptionDetails":{"partitionFileVault2State":"ENCRYPTED"}},"security":{"firewallEnabled":true}},
			  {"id":"2","general":{"name":"mbp-eve"},"operatingSystem":{"version":"12.7"},"userAndLocation":{"username":"eve"},"diskEncryption":{"bootPartitionEncryptionDetails":{"partitionFileVault2State":"NOT_ENCRYPTED"}},"security":{"firewallEnabled":false}},
			  {"id":"3","general":{"name":"mbp-mid"},"diskEncryption":{"bootPartitionEncryptionDetails":{"partitionFileVault2State":"ENCRYPTING"}},"security":{}}
			]}`)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestJamfMintsTokenFromAPIClientAndMapsStates(t *testing.T) {
	srv := jamfServer(t, "minted")
	defer srv.Close()
	j := &Jamf{BaseURL: srv.URL, ClientID: "cid", ClientSecret: "csec", HTTP: srv.Client()}
	devs, rep, err := j.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Devices != 3 || len(rep.ProviderLimits) < 2 {
		t.Fatalf("report: %+v", rep)
	}
	dana := devByName(t, devs, "mbp-dana")
	if dana.DiskEncrypted == nil || !*dana.DiskEncrypted || dana.FirewallOn == nil || !*dana.FirewallOn || dana.Owner != "dana@acme.io" {
		t.Errorf("dana: %+v", dana)
	}
	eve := devByName(t, devs, "mbp-eve")
	if eve.DiskEncrypted == nil || *eve.DiskEncrypted || eve.FirewallOn == nil || *eve.FirewallOn || eve.Owner != "eve" {
		t.Errorf("eve: NOT_ENCRYPTED + firewall false must be two definite falses: %+v", eve)
	}
	mid := devByName(t, devs, "mbp-mid")
	if mid.DiskEncrypted != nil {
		t.Error("ENCRYPTING is mid-transition — neither protected nor a finding; must be nil")
	}
	if mid.FirewallOn != nil {
		t.Error("a security section without firewallEnabled must leave the firewall unreported")
	}
	for _, d := range devs {
		if d.ScreenLock != nil || d.EDR != nil || d.AutoUpdate != nil {
			t.Errorf("Jamf inventory does not carry these: %+v", d)
		}
	}
}

func TestJamfBearerTokenPathAndRejection(t *testing.T) {
	srv := jamfServer(t, "static")
	defer srv.Close()
	if _, rep, err := (&Jamf{BaseURL: srv.URL, Token: "static", HTTP: srv.Client()}).Fetch(context.Background()); err != nil || rep.Devices != 3 {
		t.Fatalf("bearer path: %v %+v", err, rep)
	}
	if _, _, err := (&Jamf{BaseURL: srv.URL, Token: "expired", HTTP: srv.Client()}).Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expired bearer must be a 401 error, got %v", err)
	}
	if _, _, err := (&Jamf{BaseURL: srv.URL, ClientID: "cid", ClientSecret: "nope", HTTP: srv.Client()}).Fetch(context.Background()); err == nil {
		t.Fatal("a rejected API client must fail the fetch")
	}
}

// --- Intune ---

func TestIntuneFollowsNextLinkAndReadsOnlyLiteralJailbreak(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer graph" {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":{"code":"Forbidden","message":"Application is not authorized to perform this operation."}}`)
			return
		}
		if r.URL.Path != "/v1.0/deviceManagement/managedDevices" {
			w.WriteHeader(404)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `{"value":[{"deviceName":"pixel-gus","operatingSystem":"Android","osVersion":"14","isEncrypted":true,"jailBroken":"True","userPrincipalName":"gus@acme.io"}]}`)
			return
		}
		if !strings.Contains(r.URL.RawQuery, "isEncrypted") {
			t.Errorf("$select must ask for the posture fields, got %s", r.URL.RawQuery)
		}
		next, _ := json.Marshal(srv.URL + "/v1.0/deviceManagement/managedDevices?page=2")
		fmt.Fprintf(w, `{"@odata.nextLink":%s,"value":[
		  {"deviceName":"win-fay","operatingSystem":"Windows","osVersion":"10.0.22631","isEncrypted":false,"jailBroken":"Unknown","lastSyncDateTime":"2026-08-29T08:00:00Z","userPrincipalName":"fay@acme.io"},
		  {"deviceName":"mac-hal","operatingSystem":"macOS","osVersion":"14.5","isEncrypted":true,"jailBroken":"False","emailAddress":"hal@acme.io"}
		]}`, next)
	}))
	defer srv.Close()
	in := &Intune{APIBase: srv.URL, Token: "graph", HTTP: srv.Client()}
	devs, rep, err := in.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Devices != 3 {
		t.Fatalf("nextLink must be followed: got %d devices", rep.Devices)
	}
	fay := devByName(t, devs, "win-fay")
	if fay.OS != "windows" || fay.DiskEncrypted == nil || *fay.DiskEncrypted || fay.Jailbroken {
		t.Errorf("fay: unencrypted Windows, jailBroken Unknown must NOT be tampered: %+v", fay)
	}
	hal := devByName(t, devs, "mac-hal")
	if hal.Owner != "hal@acme.io" || hal.Jailbroken {
		t.Errorf("hal: %+v", hal)
	}
	gus := devByName(t, devs, "pixel-gus")
	if !gus.Jailbroken || gus.OS != "android" {
		t.Errorf("gus: literal True → tampered: %+v", gus)
	}
	fs := deviceposture.Assess(devs, deviceposture.Options{})
	var rules []string
	for _, f := range fs {
		rules = append(rules, f.RuleID)
	}
	if len(fs) != 2 || !strings.Contains(strings.Join(rules, ","), "disk-unencrypted") || !strings.Contains(strings.Join(rules, ","), "tampered") {
		t.Errorf("exactly fay's disk and gus's jailbreak should fire, got %v", rules)
	}

	if _, _, err := (&Intune{APIBase: srv.URL, Token: "no-scope", HTTP: srv.Client()}).Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a missing Graph consent must surface as the 403 it is, got %v", err)
	}
}

// --- New (config → fetcher) ---

func TestNewRefusesUnusableConfigs(t *testing.T) {
	open := func(ref string) (string, error) {
		if strings.HasPrefix(ref, "ok:") {
			return strings.TrimPrefix(ref, "ok:"), nil
		}
		return "", fmt.Errorf("unknown ref")
	}
	cases := map[string]*platform.MDMConfig{
		"nil":                nil,
		"unknown provider":   {Provider: "mosyle", TokenRef: "ok:t"},
		"kandji no token":    {Provider: platform.MDMKandji, BaseURL: "https://x.api.kandji.io"},
		"kandji bad ref":     {Provider: platform.MDMKandji, BaseURL: "https://x.api.kandji.io", TokenRef: "bad"},
		"jamf no credential": {Provider: platform.MDMJamf, BaseURL: "https://x.jamfcloud.com"},
		"jamf half a client": {Provider: platform.MDMJamf, BaseURL: "https://x.jamfcloud.com", ClientID: "cid"},
		"intune nothing":     {Provider: platform.MDMIntune},
	}
	for name, cfg := range cases {
		if _, err := New(cfg, Options{Open: open}); err == nil {
			t.Errorf("%s: must be refused at construction, not fail at 3 a.m.", name)
		}
	}
}

func TestNewBuildsEachProviderAndIntuneBorrowsTheM365Token(t *testing.T) {
	open := func(ref string) (string, error) { return strings.TrimPrefix(ref, "ok:"), nil }
	if f, err := New(&platform.MDMConfig{Provider: platform.MDMKandji, BaseURL: "https://x.api.kandji.io", TokenRef: "ok:kt"}, Options{Open: open}); err != nil || f.(*Kandji).Token != "kt" {
		t.Errorf("kandji: %v %+v", err, f)
	}
	if f, err := New(&platform.MDMConfig{Provider: platform.MDMJamf, BaseURL: "https://x.jamfcloud.com", ClientID: "cid", ClientSecretRef: "ok:cs"}, Options{Open: open}); err != nil || f.(*Jamf).ClientSecret != "cs" {
		t.Errorf("jamf client: %v", err)
	}
	if f, err := New(&platform.MDMConfig{Provider: platform.MDMJamf, BaseURL: "https://x.jamfcloud.com", TokenRef: "ok:bt"}, Options{Open: open}); err != nil || f.(*Jamf).Token != "bt" {
		t.Errorf("jamf bearer: %v", err)
	}
	if f, err := New(&platform.MDMConfig{Provider: platform.MDMIntune, TokenRef: "ok:own"}, Options{Open: open, GraphToken: "borrowed"}); err != nil || f.(*Intune).Token != "own" {
		t.Errorf("intune with its own token must use it: %v", err)
	}
	if f, err := New(&platform.MDMConfig{Provider: platform.MDMIntune}, Options{Open: open, GraphToken: "borrowed", GraphBase: "https://graph.example"}); err != nil || f.(*Intune).Token != "borrowed" || f.(*Intune).APIBase != "https://graph.example" {
		t.Errorf("intune without a token borrows the M365 connection's: %v", err)
	}
}

func TestNormalizeOS(t *testing.T) {
	for in, want := range map[string]string{"Mac": "macos", "macOS": "macos", "Windows": "windows", "iPhone": "ios", "iPad": "ios", "iOS": "ios", "Android": "android", "Linux": "linux", "ChromeOS": "chromeos"} {
		if got := normalizeOS(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}

var _ = b // keep the helper available for future cases

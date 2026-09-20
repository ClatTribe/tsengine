// Package mdm is the FETCH half of device posture — the connector docs/integrations.md §3.1 called
// "highest value, lowest effort". internal/deviceposture assesses a device inventory and has always
// been able to; what did not exist was any way for that inventory to arrive except a customer
// scripting their MDM's API and POSTing the result. This package reads Kandji, Jamf Pro and
// Microsoft Intune directly and hands deviceposture.Device records to the same ingest.
//
// # What each fetcher may and may not say
//
// deviceposture.Device carries its five protective settings as POINTERS because absent and false
// are different facts, and that contract is the whole discipline here. Every fetcher sets a
// pointer ONLY where the provider's API reported the setting for that device. A field the
// provider does not expose per device is left nil — it lands in checks_not_run as "not assessed"
// rather than being read as compliant, and Report.ProviderLimits names it so the customer knows
// which settings this MDM's API cannot answer at all (a limit of the provider, not a fetch that
// failed; the remedy is different).
//
// The consequence is that a fetcher's mistake can only ever fail in one direction: a field we
// misread as absent produces "not assessed", never a finding about a setting the device did not
// report. A device inventory that comes back EMPTY is reported as zero devices — an empty fleet is
// a legitimate answer — but a response we cannot decode at all is an error, because a login page
// served with a 200 must not become "0 devices, nothing to report".
//
// # Why per-device detail reads are bounded
//
// Kandji lists devices cheaply and puts FileVault state behind a per-device detail call. A fleet of
// five thousand laptops would be five thousand requests per sync, so the detail pass is capped
// (MaxDetail) and every device beyond the cap is NAMED in Report.Unread with its disk state left
// unreported. A partial read declared is honest; a partial read rendered as a full one is the
// "we looked at your fleet" overclaim §10 forbids.
package mdm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/deviceposture"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Fetcher pulls the live device inventory from one MDM.
type Fetcher interface {
	Fetch(ctx context.Context) ([]deviceposture.Device, Report, error)
}

// Report says what a fetch could and could not see. It travels with the devices so the ingest
// can put the provider's limits into checks_not_run beside the per-device gaps.
type Report struct {
	Provider string `json:"provider"`
	Devices  int    `json:"devices"`
	// ProviderLimits are the protective settings this provider's API does NOT report per device.
	// Distinct from a device that simply omitted a field: the customer cannot fix these by
	// changing an export, and telling them to would send them to the wrong place.
	ProviderLimits []string `json:"provider_limits,omitempty"`
	// Unread names devices the fetch listed but could not fully read (a detail call failed or
	// was skipped by the cap). Their settings are left unreported, and the name is here so the
	// silence is attributable.
	Unread []string `json:"unread,omitempty"`
}

// Providers is the set of MDMs a config may name.
func Providers() []string { return []string{platform.MDMKandji, platform.MDMJamf, platform.MDMIntune} }

// ValidProvider reports whether p names a fetcher this package has.
func ValidProvider(p string) bool {
	for _, q := range Providers() {
		if q == p {
			return true
		}
	}
	return false
}

// Options are the environment a fetcher needs beyond its config: how to open a sealed
// credential, an HTTP client (the caller chooses the SSRF-guarded one in production), and — for
// Intune only — a Graph token to borrow when the config carries none of its own.
type Options struct {
	Open func(ref string) (string, error)
	HTTP *http.Client
	// GraphToken is the onboarded Microsoft 365 connection's token, offered to Intune when the
	// config has no token of its own. Empty means no connection to borrow from.
	GraphToken string
	// GraphBase overrides the Microsoft Graph endpoint (tests). Empty means the public host.
	GraphBase string
}

// New builds the fetcher a tenant's MDMConfig describes. It refuses a config it cannot
// authenticate with rather than returning a fetcher that will fail later with a less useful
// error — "no credential" at configuration time beats "401" at 3 a.m. on a monitoring pass.
func New(cfg *platform.MDMConfig, o Options) (Fetcher, error) {
	if cfg == nil {
		return nil, fmt.Errorf("mdm: no device-management source configured")
	}
	open := o.Open
	if open == nil {
		open = func(string) (string, error) { return "", fmt.Errorf("mdm: no secret store to open credentials") }
	}
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	switch cfg.Provider {
	case platform.MDMKandji:
		if cfg.TokenRef == "" {
			return nil, fmt.Errorf("mdm: kandji needs an API token")
		}
		tok, err := open(cfg.TokenRef)
		if err != nil || tok == "" {
			return nil, fmt.Errorf("mdm: could not open the Kandji API token")
		}
		return &Kandji{BaseURL: cfg.BaseURL, Token: tok, HTTP: hc}, nil
	case platform.MDMJamf:
		j := &Jamf{BaseURL: cfg.BaseURL, HTTP: hc}
		switch {
		case cfg.ClientID != "" && cfg.ClientSecretRef != "":
			sec, err := open(cfg.ClientSecretRef)
			if err != nil || sec == "" {
				return nil, fmt.Errorf("mdm: could not open the Jamf client secret")
			}
			j.ClientID, j.ClientSecret = cfg.ClientID, sec
		case cfg.TokenRef != "":
			tok, err := open(cfg.TokenRef)
			if err != nil || tok == "" {
				return nil, fmt.Errorf("mdm: could not open the Jamf bearer token")
			}
			j.Token = tok
		default:
			return nil, fmt.Errorf("mdm: jamf needs an API client (id + secret) or a bearer token")
		}
		return j, nil
	case platform.MDMIntune:
		tok := ""
		if cfg.TokenRef != "" {
			t, err := open(cfg.TokenRef)
			if err != nil || t == "" {
				return nil, fmt.Errorf("mdm: could not open the Intune Graph token")
			}
			tok = t
		} else {
			tok = o.GraphToken
		}
		if tok == "" {
			return nil, fmt.Errorf("mdm: intune needs a Graph token, or a connected Microsoft 365 tenant to borrow one from")
		}
		return &Intune{APIBase: o.GraphBase, Token: tok, HTTP: hc}, nil
	}
	return nil, fmt.Errorf("mdm: unknown provider %q", cfg.Provider)
}

// --- shared HTTP ---

// httpDoer is what a fetcher needs from an HTTP client; *http.Client satisfies it and tests can
// substitute a recorder.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// getJSON performs one authenticated GET and decodes the body. A non-2xx status is an error that
// carries the status and the first line of the body, because "401" alone does not tell an operator
// whether the token expired or the tenant URL is wrong. A 2xx whose body does not decode into the
// expected shape is ALSO an error: that is what an HTML login page looks like, and reading it as
// an empty fleet is the silent-clean failure this whole package exists to avoid.
func getJSON(ctx context.Context, hc httpDoer, url string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, firstLine(body))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s: response is not the expected JSON (%v): %s", url, err, firstLine(body))
	}
	return nil
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func ptr(b bool) *bool { return &b }

// normalizeOS maps a provider's platform label onto deviceposture's vocabulary. Anything
// unrecognised is passed through lower-cased rather than guessed at.
func normalizeOS(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(l, "mac"):
		return "macos"
	case strings.HasPrefix(l, "win"):
		return "windows"
	case strings.HasPrefix(l, "ipad"), strings.HasPrefix(l, "iphone"), l == "ios", l == "ipados":
		return "ios"
	case strings.HasPrefix(l, "android"):
		return "android"
	case strings.HasPrefix(l, "linux"), strings.HasPrefix(l, "ubuntu"):
		return "linux"
	}
	return l
}

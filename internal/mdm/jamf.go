package mdm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ClatTribe/tsengine/internal/deviceposture"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Jamf reads Jamf Pro's computer inventory through the Jamf Pro API (not the Classic API): one
// paged call over the sections that carry posture. Auth is either an API client (id + secret,
// exchanged for a short-lived bearer per sync — the standing-integration shape, since a Jamf
// bearer expires in thirty minutes) or a bearer the customer minted themselves.
//
// What the inventory reports per computer: name, OS version, assigned user, last contact,
// FileVault state (DISK_ENCRYPTION section) and the host firewall (SECURITY section). Screen lock,
// EDR presence and automatic-update policy are configuration-profile matters and are not device
// state in these sections, so they stay nil and are declared. Mobile devices live behind a
// different endpoint and are not fetched — the report says so rather than implying the fleet is
// laptops only.
type Jamf struct {
	BaseURL      string
	Token        string
	ClientID     string
	ClientSecret string
	HTTP         httpDoer
}

const jamfPageSize = 100

type jamfInventory struct {
	TotalCount int `json:"totalCount"`
	Results    []struct {
		ID      string `json:"id"`
		General struct {
			Name            string `json:"name"`
			LastContactTime string `json:"lastContactTime"`
		} `json:"general"`
		OperatingSystem struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"operatingSystem"`
		UserAndLocation struct {
			Email    string `json:"email"`
			Username string `json:"username"`
		} `json:"userAndLocation"`
		DiskEncryption struct {
			BootPartition struct {
				FileVault2State string `json:"partitionFileVault2State"`
			} `json:"bootPartitionEncryptionDetails"`
		} `json:"diskEncryption"`
		Security struct {
			FirewallEnabled *bool `json:"firewallEnabled"`
		} `json:"security"`
	} `json:"results"`
}

func (j *Jamf) Fetch(ctx context.Context) ([]deviceposture.Device, Report, error) {
	rep := Report{Provider: platform.MDMJamf, ProviderLimits: []string{
		"Jamf Pro's computer inventory does not report screen lock, EDR presence or automatic-update policy as device state (they are configuration profiles), so those three settings are not assessed from this source",
		"only computers are read; mobile devices enrolled in Jamf are not included in this inventory",
	}}
	base := strings.TrimRight(j.BaseURL, "/")
	if base == "" {
		return nil, rep, fmt.Errorf("jamf: base URL is required (https://<tenant>.jamfcloud.com)")
	}
	tok := j.Token
	if j.ClientID != "" && j.ClientSecret != "" {
		t, err := j.mintToken(ctx, base)
		if err != nil {
			return nil, rep, err
		}
		tok = t
	}
	if tok == "" {
		return nil, rep, fmt.Errorf("jamf: no credential")
	}
	hdr := map[string]string{"Authorization": "Bearer " + tok}

	q := url.Values{}
	for _, s := range []string{"GENERAL", "OPERATING_SYSTEM", "USER_AND_LOCATION", "DISK_ENCRYPTION", "SECURITY"} {
		q.Add("section", s)
	}
	q.Set("page-size", fmt.Sprint(jamfPageSize))
	q.Set("sort", "id:asc")

	var out []deviceposture.Device
	for page := 0; ; page++ {
		q.Set("page", fmt.Sprint(page))
		var inv jamfInventory
		if err := getJSON(ctx, j.HTTP, base+"/api/v1/computers-inventory?"+q.Encode(), hdr, &inv); err != nil {
			return nil, rep, fmt.Errorf("jamf: computers inventory: %w", err)
		}
		for _, r := range inv.Results {
			if strings.TrimSpace(r.General.Name) == "" {
				continue
			}
			d := deviceposture.Device{
				Name: r.General.Name, OS: "macos", OSVersion: r.OperatingSystem.Version,
				LastCheckIn: r.General.LastContactTime,
				Owner:       firstNonEmpty(r.UserAndLocation.Email, r.UserAndLocation.Username),
			}
			// Only the two definite states are asserted. ENCRYPTING / DECRYPTING / UNKNOWN / empty
			// leave the pointer nil: a disk mid-transition is neither protected nor a finding.
			switch strings.ToUpper(r.DiskEncryption.BootPartition.FileVault2State) {
			case "ENCRYPTED":
				d.DiskEncrypted = ptr(true)
			case "NOT_ENCRYPTED":
				d.DiskEncrypted = ptr(false)
			}
			d.FirewallOn = r.Security.FirewallEnabled
			out = append(out, d)
		}
		if len(inv.Results) < jamfPageSize || (page+1)*jamfPageSize >= inv.TotalCount {
			break
		}
	}
	rep.Devices = len(out)
	return out, rep, nil
}

// mintToken exchanges the API client for a bearer via Jamf's client-credentials grant.
func (j *Jamf) mintToken(ctx context.Context, base string) (string, error) {
	form := url.Values{"client_id": {j.ClientID}, "client_secret": {j.ClientSecret}, "grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := j.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("jamf: token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("jamf: token: HTTP %d: %s", resp.StatusCode, firstLine(body))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", fmt.Errorf("jamf: token: no access_token in response")
	}
	return tr.AccessToken, nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

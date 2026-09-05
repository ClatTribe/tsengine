package mdm

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/deviceposture"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Intune reads Microsoft Intune's managed-device list through Microsoft Graph. The token needs
// DeviceManagementManagedDevices.Read.All; when the tenant supplied none, the caller offers the
// onboarded Microsoft 365 connection's token, and a 403 from Graph is surfaced as itself so the
// customer knows which consent is missing rather than seeing an empty fleet.
//
// What managedDevices reports per device: name, platform, OS version, primary user, last sync,
// encryption state and jailbreak state. The four other protective settings are compliance-policy
// evaluations rather than device properties in this resource, so they stay nil and are declared.
type Intune struct {
	APIBase string // empty → https://graph.microsoft.com
	Token   string
	HTTP    httpDoer
}

type graphDevices struct {
	NextLink string `json:"@odata.nextLink"`
	Value    []struct {
		DeviceName        string `json:"deviceName"`
		OperatingSystem   string `json:"operatingSystem"`
		OSVersion         string `json:"osVersion"`
		IsEncrypted       *bool  `json:"isEncrypted"`
		JailBroken        string `json:"jailBroken"`
		LastSyncDateTime  string `json:"lastSyncDateTime"`
		UserPrincipalName string `json:"userPrincipalName"`
		EmailAddress      string `json:"emailAddress"`
	} `json:"value"`
}

func (in *Intune) Fetch(ctx context.Context) ([]deviceposture.Device, Report, error) {
	rep := Report{Provider: platform.MDMIntune, ProviderLimits: []string{
		"Intune's managed-device record does not carry screen lock, host firewall, EDR presence or automatic-update state (those are compliance-policy evaluations), so those four settings are not assessed from this source",
	}}
	base := strings.TrimRight(in.APIBase, "/")
	if base == "" {
		base = "https://graph.microsoft.com"
	}
	if in.Token == "" {
		return nil, rep, fmt.Errorf("intune: no Graph token")
	}
	hdr := map[string]string{"Authorization": "Bearer " + in.Token}
	url := base + "/v1.0/deviceManagement/managedDevices?$select=deviceName,operatingSystem,osVersion,isEncrypted,jailBroken,lastSyncDateTime,userPrincipalName,emailAddress&$top=200"

	var out []deviceposture.Device
	for url != "" {
		var page graphDevices
		if err := getJSON(ctx, in.HTTP, url, hdr, &page); err != nil {
			return nil, rep, fmt.Errorf("intune: managed devices: %w", err)
		}
		for _, v := range page.Value {
			if strings.TrimSpace(v.DeviceName) == "" {
				continue
			}
			d := deviceposture.Device{
				Name: v.DeviceName, OS: normalizeOS(v.OperatingSystem), OSVersion: v.OSVersion,
				LastCheckIn: v.LastSyncDateTime, Owner: firstNonEmpty(v.UserPrincipalName, v.EmailAddress),
				DiskEncrypted: v.IsEncrypted,
			}
			// Graph spells this as a string: "True", "False" or "Unknown". Only the literal
			// affirmative is a tampered device — the same rule the KEV ingest applies to
			// ransomware use, where treating any non-empty value as a yes mislabels the majority.
			d.Jailbroken = strings.EqualFold(strings.TrimSpace(v.JailBroken), "true")
			out = append(out, d)
		}
		url = page.NextLink
	}
	rep.Devices = len(out)
	return out, rep, nil
}

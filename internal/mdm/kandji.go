package mdm

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/deviceposture"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Kandji reads a Kandji tenant's device list and, per device, the detail record that carries
// FileVault state. Auth is a bearer API token minted in Kandji's Settings → Access; the base URL
// is the tenant's own (https://<sub>.api.kandji.io).
//
// What Kandji's API reports per device: name, platform, OS version, assigned user, last check-in
// and (Mac, via the detail call) FileVault. Screen lock, the host firewall, EDR presence and
// automatic updates are enforced through Library items and are NOT reported as device state, so
// they stay nil and are declared in Report.ProviderLimits.
type Kandji struct {
	BaseURL string
	Token   string
	HTTP    httpDoer
	// MaxDetail caps the per-device detail pass. 0 means the default (1000). Devices beyond it are
	// listed with disk state unreported and named in Report.Unread.
	MaxDetail int
}

const kandjiPageSize = 300

// kandjiDevice is the list-endpoint record. Kandji returns a bare JSON array.
type kandjiDevice struct {
	DeviceID    string `json:"device_id"`
	DeviceName  string `json:"device_name"`
	Platform    string `json:"platform"`
	OSVersion   string `json:"os_version"`
	LastCheckIn string `json:"last_check_in"`
	IsRemoved   bool   `json:"is_removed"`
	User        struct {
		Email string `json:"email"`
	} `json:"user"`
}

// kandjiDetail is the subset of the detail record we read. The spellings are enumerated rather
// than bet on: Kandji nests FileVault under "filevault" and some exports flatten it. A shape we
// do not recognise leaves the pointer nil — "not reported", never "off".
type kandjiDetail struct {
	General struct {
		AssignedUser struct {
			Email string `json:"email"`
		} `json:"assigned_user"`
		OSVersion   string `json:"os_version"`
		LastCheckIn string `json:"last_checkin"`
	} `json:"general"`
	FileVault struct {
		Enabled *bool `json:"filevault_enabled"`
	} `json:"filevault"`
	FileVaultEnabled *bool `json:"filevault_enabled"`
	SecurityInfo     struct {
		FileVaultEnabled *bool `json:"filevault_enabled"`
	} `json:"security_information"`
}

func (k *Kandji) Fetch(ctx context.Context) ([]deviceposture.Device, Report, error) {
	rep := Report{Provider: platform.MDMKandji, ProviderLimits: []string{
		"Kandji enforces screen lock, the host firewall, EDR and automatic updates through Library items and does not report them as per-device state, so those four settings are not assessed from this source",
	}}
	base := strings.TrimRight(k.BaseURL, "/")
	if base == "" {
		return nil, rep, fmt.Errorf("kandji: base URL is required (https://<subdomain>.api.kandji.io)")
	}
	hdr := map[string]string{"Authorization": "Bearer " + k.Token}

	var all []kandjiDevice
	for offset := 0; ; offset += kandjiPageSize {
		var page []kandjiDevice
		url := fmt.Sprintf("%s/api/v1/devices?limit=%d&offset=%d", base, kandjiPageSize, offset)
		if err := getJSON(ctx, k.HTTP, url, hdr, &page); err != nil {
			return nil, rep, fmt.Errorf("kandji: list devices: %w", err)
		}
		all = append(all, page...)
		if len(page) < kandjiPageSize {
			break
		}
	}

	max := k.MaxDetail
	if max <= 0 {
		max = 1000
	}
	var out []deviceposture.Device
	for i, kd := range all {
		if kd.IsRemoved || strings.TrimSpace(kd.DeviceName) == "" {
			continue
		}
		d := deviceposture.Device{
			Name: kd.DeviceName, Owner: kd.User.Email, OS: normalizeOS(kd.Platform),
			OSVersion: kd.OSVersion, LastCheckIn: kd.LastCheckIn,
		}
		if i >= max {
			rep.Unread = append(rep.Unread, kd.DeviceName)
			out = append(out, d)
			continue
		}
		var det kandjiDetail
		if err := getJSON(ctx, k.HTTP, base+"/api/v1/devices/"+kd.DeviceID+"/details", hdr, &det); err != nil {
			// One device's detail failing is not a reason to drop the whole sync, but its disk
			// state is now unknown and the name has to say so.
			rep.Unread = append(rep.Unread, kd.DeviceName)
			out = append(out, d)
			continue
		}
		if d.Owner == "" {
			d.Owner = det.General.AssignedUser.Email
		}
		if d.OSVersion == "" {
			d.OSVersion = det.General.OSVersion
		}
		if d.LastCheckIn == "" {
			d.LastCheckIn = det.General.LastCheckIn
		}
		switch {
		case det.FileVault.Enabled != nil:
			d.DiskEncrypted = det.FileVault.Enabled
		case det.FileVaultEnabled != nil:
			d.DiskEncrypted = det.FileVaultEnabled
		case det.SecurityInfo.FileVaultEnabled != nil:
			d.DiskEncrypted = det.SecurityInfo.FileVaultEnabled
		}
		out = append(out, d)
	}
	rep.Devices = len(out)
	return out, rep, nil
}

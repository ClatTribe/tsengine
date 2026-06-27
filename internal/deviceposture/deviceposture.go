// Package deviceposture is ENDPOINT / DEVICE POSTURE (MDM-lite) — the employee-device "finding issues"
// capability the compliance leaders (Vanta device monitoring) have that the engine lacked. Employee laptops
// and phones are an asset class an "in-depth analysis of the assets" must cover: an unencrypted disk, an
// end-of-life OS, a tampered (jailbroken/rooted) device, or a missing screen lock / firewall / EDR are all
// real risks that fail SOC 2 / CIS / HIPAA workstation controls.
//
// Assess turns a device inventory snapshot into grounded device-posture findings, each mapped to the
// endpoint controls (SOC 2 CC6.7/CC6.8/CC7.1, CIS Controls 1/3/4/7/10, NIST SC-28/SI-2/SI-3, HIPAA
// 164.310(d)/164.312(a)(2)(iv), ISO 27001 A.8.1). Snapshot-driven, LLM-free, grounded (§10): it acts only
// on a device's own recorded attributes, and a fully-compliant fleet yields ZERO findings. Mirrors the
// SSPM / OSINT / tprm assessors; the live driver (POST /v1/devices/ingest) lands findings in the same store,
// so device risk flows through issues / incidents / grc / hitl like any finding. A live MDM connector
// (Kandji / Jamf / Intune / Kolide export) is the documented follow-on; the posted-inventory path works today.
package deviceposture

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Device is one endpoint in the fleet — its posture attributes as reported by an MDM/agent or recorded by
// the team. Every field is a stated fact, never inferred. Bool fields default to the INSECURE reading only
// where the inventory explicitly says so (a missing field is not a finding — absent data never invents risk).
type Device struct {
	Name          string `json:"name"`
	Owner         string `json:"owner,omitempty"` // employee email
	OS            string `json:"os,omitempty"`    // macos | windows | linux | ios | android
	OSVersion     string `json:"os_version,omitempty"`
	DiskEncrypted bool   `json:"disk_encrypted"`           // FileVault / BitLocker / LUKS on
	ScreenLock    bool   `json:"screen_lock"`              // auto-lock / password-on-wake enabled
	FirewallOn    bool   `json:"firewall_on"`              // host firewall enabled
	EDR           bool   `json:"edr"`                      // antivirus / EDR agent present
	AutoUpdate    bool   `json:"auto_update"`              // automatic OS updates enabled
	OSEndOfLife   bool   `json:"os_end_of_life,omitempty"` // the OS version is past vendor support
	Jailbroken    bool   `json:"jailbroken,omitempty"`     // jailbroken / rooted (tampered)
	LastCheckIn   string `json:"last_check_in,omitempty"`  // RFC3339 / "2006-01-02"
}

// Options tunes the assessment.
type Options struct {
	Now   func() time.Time
	NewID func() string
}

// Assess turns the device inventory into grounded posture findings. A compliant fleet (encrypted, locked,
// firewalled, supported OS, EDR present, not tampered) yields nil.
func Assess(devices []Device, opts Options) []types.Finding {
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now()
	}
	n := 0
	id := func() string {
		n++
		if opts.NewID != nil {
			return opts.NewID()
		}
		return fmt.Sprintf("dev-%d", n)
	}

	var out []types.Finding
	for _, dv := range devices {
		name := strings.TrimSpace(dv.Name)
		if name == "" {
			continue
		}
		who := name
		if dv.Owner != "" {
			who = name + " (" + dv.Owner + ")"
		}

		if !dv.DiskEncrypted {
			out = append(out, finding(id(), "deviceposture::disk-unencrypted", types.SeverityHigh,
				"Device disk is not encrypted: "+who, name,
				fmt.Sprintf("%s has no full-disk encryption — if it's lost or stolen, all data on it is readable. Enable FileVault / BitLocker / LUKS and enforce it via MDM.", who),
				now, comp(types.Compliance{SOC2: []string{"CC6.7"}, PCI: []string{"3.4.1"}, HIPAA: []string{"164.312(a)(2)(iv)"}, GDPR: []string{"Art. 32"}, CISv8: []string{"3.6"}, NISTCSF: []string{"PR.DS-1"}, NIST80053: []string{"SC-28"}, ISO27001: []string{"A.8.1"}})))
		}
		if dv.Jailbroken {
			out = append(out, finding(id(), "deviceposture::tampered", types.SeverityHigh,
				"Device is jailbroken / rooted: "+who, name,
				fmt.Sprintf("%s is jailbroken/rooted — its OS security model is broken and it cannot be trusted with corporate data. Block it from access and re-image.", who),
				now, comp(types.Compliance{SOC2: []string{"CC6.8"}, CISv8: []string{"4.1"}, NISTCSF: []string{"PR.IP-1"}, NIST80053: []string{"CM-5", "SI-7"}, ISO27001: []string{"A.8.1"}})))
		}
		if dv.OSEndOfLife {
			out = append(out, finding(id(), "deviceposture::os-end-of-life", types.SeverityHigh,
				"Device runs an end-of-life OS: "+who, name,
				fmt.Sprintf("%s runs %s, which is past vendor support and no longer receives security patches — a standing unpatched-vulnerability risk. Upgrade to a supported OS version.", who, nz(dv.OSVersion, dv.OS)),
				now, comp(types.Compliance{SOC2: []string{"CC7.1"}, PCI: []string{"6.3.3"}, CISv8: []string{"2.2", "7.3"}, NISTCSF: []string{"ID.AM-2", "PR.IP-12"}, NIST80053: []string{"SI-2"}})))
		}
		if !dv.ScreenLock {
			out = append(out, finding(id(), "deviceposture::no-screen-lock", types.SeverityMedium,
				"Device has no auto screen-lock: "+who, name,
				fmt.Sprintf("%s does not auto-lock — an unattended, unlocked device is an open door to corporate data and sessions. Enforce a short auto-lock + password-on-wake via MDM.", who),
				now, comp(types.Compliance{SOC2: []string{"CC6.1"}, HIPAA: []string{"164.310(d)(1)"}, CISv8: []string{"4.3"}, NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-11"}})))
		}
		if !dv.FirewallOn {
			out = append(out, finding(id(), "deviceposture::firewall-off", types.SeverityMedium,
				"Device host firewall is off: "+who, name,
				fmt.Sprintf("%s has its host firewall disabled — inbound network exposure on untrusted networks. Enable and enforce the host firewall.", who),
				now, comp(types.Compliance{SOC2: []string{"CC6.6"}, CISv8: []string{"4.5"}, NISTCSF: []string{"PR.AC-5"}, NIST80053: []string{"SC-7"}})))
		}
		if !dv.EDR {
			out = append(out, finding(id(), "deviceposture::no-edr", types.SeverityMedium,
				"Device has no antivirus / EDR: "+who, name,
				fmt.Sprintf("%s has no endpoint antivirus / EDR agent — malware and intrusions go undetected on it. Deploy and enforce an EDR agent.", who),
				now, comp(types.Compliance{SOC2: []string{"CC7.1"}, PCI: []string{"5.2.1"}, HIPAA: []string{"164.308(a)(5)(ii)(B)"}, CISv8: []string{"10.1"}, NISTCSF: []string{"DE.CM-4"}, NIST80053: []string{"SI-3"}})))
		}
		if !dv.AutoUpdate {
			out = append(out, finding(id(), "deviceposture::auto-update-off", types.SeverityLow,
				"Device automatic updates are off: "+who, name,
				fmt.Sprintf("%s does not auto-install OS security updates — patches lag, widening the window of exposure. Enable automatic updates via MDM.", who),
				now, comp(types.Compliance{SOC2: []string{"CC7.1"}, CISv8: []string{"7.3", "7.4"}, NISTCSF: []string{"PR.IP-12"}, NIST80053: []string{"SI-2"}})))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

func finding(fid, rule string, sev types.Severity, title, endpoint, desc string, now time.Time, c *types.Compliance) types.Finding {
	return types.Finding{
		ID: fid, RuleID: rule, Tool: "deviceposture", Severity: sev,
		Title: title, Endpoint: "device:" + endpoint, Description: desc,
		DiscoveredAt: now, VerificationStatus: types.VerificationVerified, Compliance: c,
	}
}

func comp(c types.Compliance) *types.Compliance { return &c }

func nz(s, dflt string) string {
	if strings.TrimSpace(s) == "" {
		return dflt
	}
	return s
}

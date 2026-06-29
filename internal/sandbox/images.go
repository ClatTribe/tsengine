package sandbox

import "strings"

// Images is the per-purpose sandbox image set — the two-image split (docs/product-restructure.md P4).
// One bulky sandbox carried BOTH the detection toolset and the would-be exploitation toolset; splitting it
// gives two leaner images:
//
//   - Scan    — the DETECTION toolset (SAST/SCA/CSPM/recon — the bulk: semgrep, codeql, trivy, prowler,
//               grype, katana, …). Used by the per-asset scan dispatcher.
//   - Pentest — the leaner EXPLOITATION toolset (sqlmap, dalfox, nuclei DAST, a headless browser for
//               DOM-XSS proof, an OAST client). The AI Pentester's sandbox-backed re-fires + proof channels.
//
// The active-exploitation Prober is host-side today (TSENGINE_ACTIVE_EXPLOIT); the pentest image backs the
// sandbox-gated proof channels (browser/OAST) and future sandboxed tool re-fires.
type Images struct {
	Scan    string // detection/scan sandbox (TSENGINE_SANDBOX_IMAGE)
	Pentest string // exploitation sandbox (TSENGINE_PENTEST_SANDBOX_IMAGE)
}

// ResolveImages picks the per-purpose images. The pentest image GRACEFULLY FALLS BACK to the scan image
// when its env is unset — so a single-image deployment is unchanged (the scan image already carries the
// exploit tools today). Set TSENGINE_PENTEST_SANDBOX_IMAGE to the leaner pentest-sandbox image once it's
// built (docker/pentest-sandbox/Dockerfile) to actually split the two.
func ResolveImages(scanImage, pentestEnv string) Images {
	scan := strings.TrimSpace(scanImage)
	pentest := strings.TrimSpace(pentestEnv)
	if pentest == "" {
		pentest = scan // fallback — one image until the split image is built + configured
	}
	return Images{Scan: scan, Pentest: pentest}
}

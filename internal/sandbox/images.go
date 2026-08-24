package sandbox

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Images is the per-purpose sandbox image set — the two-image split (docs/product-restructure.md P4).
// One bulky sandbox carried BOTH the detection toolset and the would-be exploitation toolset; splitting it
// gives two leaner images:
//
//   - Scan    — the DETECTION toolset (SAST/SCA/CSPM/recon — the bulk: semgrep, codeql, trivy, prowler,
//     grype, katana, …). Used by the per-asset scan dispatcher.
//   - Pentest — the leaner EXPLOITATION toolset (sqlmap, dalfox, nuclei DAST, a headless browser for
//     DOM-XSS proof, an OAST client). The AI Pentester's sandbox-backed re-fires + proof channels.
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

// ---------------------------------------------------------------------------
// Per-asset scan images
// ---------------------------------------------------------------------------

// AssetToolset maps an asset type to the sandbox TOOLSET that carries its tools.
//
// The two vocabularies are DIFFERENT and deliberately so: asset types are the product's
// (`web_application`, `container_image`), toolsets are the image build's (`web`, `container`, the
// values docker/sandbox/toolset.sh switches on). Nothing enforced the correspondence before, because
// nothing needed it — one image carried everything. Selecting a per-asset image makes the mapping
// load-bearing, so it is written out and tested rather than derived by string-munging: deriving
// `container` from `container_image` by cutting at the underscore also turns `ip_address` into `ip`
// correctly and `cloud_account` into `cloud` correctly, and would silently produce garbage the day
// an asset type is renamed.
//
// An asset type ABSENT from this map has no slim image and must fall back to the full one. That is
// the safe direction: a slim image missing a tool stubs it to exit 127, which the tool layer reports
// as "did not run" — honest, but a scan that could have been complete comes back degraded.
var AssetToolset = map[types.AssetType]string{
	types.AssetWebApplication: "web",
	types.AssetAPI:            "api",
	types.AssetRepository:     "repository",
	types.AssetContainerImage: "container",
	types.AssetIPAddress:      "ip",
	types.AssetDomain:         "domain",
	types.AssetCloudAccount:   "cloud",
}

// ScanImages resolves which image a scan of a given asset type should run in.
type ScanImages struct {
	// Full is the always-correct image carrying every toolset. Used whenever no slim image is
	// configured for an asset, and it is the ONLY safe default.
	Full string
	// Template is an image ref containing the placeholder "{toolset}", e.g.
	// "ghcr.io/acme/tsengine/sandbox:{toolset}-latest". One env var opts a deployment into every slim
	// image at once, which is the whole point — a per-asset override list nobody maintains would
	// leave most assets on the full image while looking configured.
	Template string
	// Overrides pin a specific asset's image, beating the template. For pinning one asset to a digest
	// during an incident without moving the rest.
	Overrides map[types.AssetType]string
}

// SandboxImageTemplatePlaceholder is what Template substitutes.
const SandboxImageTemplatePlaceholder = "{toolset}"

// For returns the image to run a scan of assetType in, and whether it is a slim one.
//
// Falls back to Full on anything unrecognised — an unknown asset type, a toolset with no slim image,
// an empty template. Guessing an image name from an asset we do not model would produce a pull
// failure at scan time (or worse, someone else's image), and the full image is always correct.
func (s ScanImages) For(assetType types.AssetType) (image string, slim bool) {
	if img, ok := s.Overrides[assetType]; ok && strings.TrimSpace(img) != "" {
		return strings.TrimSpace(img), true
	}
	tpl := strings.TrimSpace(s.Template)
	if tpl == "" || !strings.Contains(tpl, SandboxImageTemplatePlaceholder) {
		return s.Full, false
	}
	toolset, ok := AssetToolset[assetType]
	if !ok {
		return s.Full, false
	}
	return strings.ReplaceAll(tpl, SandboxImageTemplatePlaceholder, toolset), true
}

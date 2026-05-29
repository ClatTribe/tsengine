// Package types defines the canonical types that cross the host/sandbox
// boundary and the JSON shape consumed by webappsec. The schema here is
// the L1 dashboard contract — see CLAUDE.md §6. Field names are stable;
// changes require coordinating with downstream consumers.
package types

// AssetType is the kind of target being scanned. See CLAUDE.md §3 for the
// seven asset types and their primary audience.
type AssetType string

const (
	AssetWebApplication AssetType = "web_application"
	AssetAPI            AssetType = "api"
	AssetRepository     AssetType = "repository"
	AssetContainerImage AssetType = "container_image"
	AssetIPAddress      AssetType = "ip_address"
	AssetDomain         AssetType = "domain"
	AssetCloudAccount   AssetType = "cloud_account"
)

// AllAssetTypes returns every supported asset type in stable order.
func AllAssetTypes() []AssetType {
	return []AssetType{
		AssetWebApplication,
		AssetAPI,
		AssetRepository,
		AssetContainerImage,
		AssetIPAddress,
		AssetDomain,
		AssetCloudAccount,
	}
}

// Valid reports whether t is a recognized asset type.
func (t AssetType) Valid() bool {
	for _, x := range AllAssetTypes() {
		if t == x {
			return true
		}
	}
	return false
}

// Asset is the scan target.
type Asset struct {
	Type   AssetType `json:"type"`
	Target string    `json:"target"`
	Scope  Scope     `json:"scope"`

	// Auth carries credentials for an authenticated scan. It is json:"-"
	// — never serialized into vulnerabilities.json, because it holds a
	// live session/credentials. Threaded to the web Handler so it can
	// wire a seed_auth stage; nil for unauthenticated scans.
	Auth *AuthConfig `json:"-"`
}

// AuthConfig configures an authenticated web scan: either a pre-obtained
// session Cookie (provided-session mode) or form-login fields seed_auth
// POSTs to capture one (basic form-login mode). Never serialized.
type AuthConfig struct {
	Cookie        string // pre-obtained session, e.g. "SESSION=abc123"
	LoginURL      string // form-login: URL to POST credentials to
	Username      string
	Password      string
	UsernameField string // form field name (default "username")
	PasswordField string // form field name (default "password")
}

// Scope constrains where anchor tools are allowed to probe. ScopeHosts
// whitelists additional hosts beyond the primary target; OutOfScope is a
// hard deny list applied after host/path filtering.
type Scope struct {
	ScopeHosts []string `json:"scope_hosts,omitempty"`
	OutOfScope []string `json:"out_of_scope,omitempty"`
}

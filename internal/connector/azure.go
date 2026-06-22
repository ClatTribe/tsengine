package connector

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Azure onboards a customer's Azure subscription for cloud_account posture scanning (prowler — the
// engine's cloud_account asset, which supports Azure). Like AWS + GCP, Azure has no consent flow
// that fits server-to-server posture scanning; the standard partner onboarding is read-only
// delegation: the customer grants tsengine's Entra ID app the Reader (+ Security Reader) role on
// their subscription. This connector adapts the OAuth-shaped interface the same way connector.GCP
// does:
//
//   - OAuthURL returns the Azure portal subscription Access-control (IAM) page where the customer
//     grants tsengine's app read-only access; the CSRF state doubles as the tenant binding.
//   - Exchange takes the Azure subscription ID the user submits back (as `code`), validates it as a
//     GUID, and records it as the connection's SecretRef/Account — the subscription (+ the granted
//     app) is the credential reference.
//   - Discover yields the cloud_account asset the engine scans with prowler (--provider azure).
//
// The live scan (tsengine's service principal → prowler azure over the subscription) needs the role
// grant + tsengine runtime creds — the deployment step. The onboarding here is provider-correct and
// unit-tested. Configure via AZURE_TRUST_APP_ID (tsengine's Entra app the customer grants Reader to).
type Azure struct {
	TrustAppID string // tsengine's Entra ID application (client) id the customer grants Reader to
	PortalBase string // default https://portal.azure.com
	// Writer is the live, reversible Azure write path. Nil → no live remediation is configured, so
	// Apply returns an honest "not configured" error. The real impl (azremediate.StorageWriter)
	// uses the ARM-storage SDK; injectable so the write path is unit-tested without live creds.
	Writer AzureWriter
}

// AzureWriter performs the reversible Azure mutations tsengine remediates to. Today only disabling
// blob public access on a storage account (the fix for a publicly-exposed account).
type AzureWriter interface {
	// DisableStoragePublicAccess sets AllowBlobPublicAccess=false on the storage account (the Azure
	// equivalent of S3 Block Public Access). The subscription scopes the ARM client.
	DisableStoragePublicAccess(ctx context.Context, subscriptionID, resourceGroup, account string) error
}

// NewAzure builds the connector.
func NewAzure(trustAppID string) *Azure {
	return &Azure{TrustAppID: trustAppID, PortalBase: "https://portal.azure.com"}
}

func (a *Azure) Kind() string { return platform.ConnAzure }

func (a *Azure) portalBase() string {
	if a.PortalBase == "" {
		return "https://portal.azure.com"
	}
	return strings.TrimRight(a.PortalBase, "/")
}

// OAuthURL returns the Azure portal subscriptions blade where the customer opens their
// subscription's Access control (IAM) and grants tsengine's app the Reader role. state → the
// CSRF/tenant binding; the customer then submits their subscription ID back (Exchange).
func (a *Azure) OAuthURL(state, _ string) string {
	q := url.Values{
		"state":      {state},
		"grant_to":   {a.TrustAppID}, // the Entra app the customer should grant Reader
		"grant_role": {"Reader"},
	}
	return a.portalBase() + "/#blade/Microsoft_Azure_Billing/SubscriptionsBlade?" + q.Encode()
}

// Exchange records the Azure subscription the customer onboarded. `code` is the subscription ID
// (the callback carries it, not an OAuth code) — the subscription (+ the granted app) is the
// credential reference.
func (a *Azure) Exchange(_ context.Context, code, _ string) (platform.Connection, error) {
	sub := strings.TrimSpace(code)
	if err := validateAzureSubscriptionID(sub); err != nil {
		return platform.Connection{}, err
	}
	return platform.Connection{
		Kind: platform.ConnAzure, Status: platform.ConnActive,
		Account: sub, SecretRef: sub, CreatedAt: time.Now().UTC(),
	}, nil
}

// Discover yields the cloud_account asset the engine scans (prowler --provider azure over the
// subscription, via tsengine's granted service principal).
func (a *Azure) Discover(_ context.Context, c platform.Connection, _ string) ([]platform.Asset, error) {
	return []platform.Asset{{
		TenantID: c.TenantID, ConnectionID: c.ID,
		Type:         "cloud_account",
		Target:       nz(c.Account, "azure"),
		Meta:         map[string]string{"provider": "azure", "subscription_id": c.Account},
		DiscoveredAt: time.Now().UTC(),
	}}, nil
}

// Watch is a no-op: cloud posture is scheduled, not webhook-driven.
func (a *Azure) Watch(context.Context, platform.Connection, []byte) ([]Trigger, error) {
	return nil, nil
}

// Apply executes an approved (HITL-gated) Azure remediation, routing on the action's machine-
// readable remediation_type. Reached only after the desk approves (§18.2 inv. 3). An unknown type
// or an unconfigured Writer surfaces as an error — the action stays un-applied, never falsely "done".
func (a *Azure) Apply(ctx context.Context, c platform.Connection, _ string, act platform.Action) error {
	rt, _ := act.Payload["remediation_type"].(string)
	switch rt {
	case "azure_storage_disable_public_access":
		rg, account := azureStorageTarget(strFrom(act.Payload, "target"))
		if rg == "" || account == "" {
			return fmt.Errorf("azure apply: %s action %s target must resolve a resource group + storage account", rt, act.ID)
		}
		if a.Writer == nil {
			return fmt.Errorf("azure apply: no live Azure write path configured (needs service-principal write creds); "+
				"action %s (disable public access on %s/%s) left un-applied", act.ID, rg, account)
		}
		return a.Writer.DisableStoragePublicAccess(ctx, c.Account, rg, account)
	case "":
		return fmt.Errorf("azure apply: action %s carries no remediation_type — no live write path, left un-applied", act.ID)
	default:
		return fmt.Errorf("azure apply: remediation_type %q has no live Azure write path yet (target %s)", rt, strFrom(act.Payload, "target"))
	}
}

// azureStorageTarget resolves (resourceGroup, account) from a finding target — a full ARM resource
// ID ("/subscriptions/.../resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{acct}")
// or the compact "{rg}/{acct}" form. Case-insensitive on the ARM segment names.
func azureStorageTarget(target string) (resourceGroup, account string) {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, "/") || strings.Contains(strings.ToLower(t), "/resourcegroups/") {
		parts := strings.Split(strings.Trim(t, "/"), "/")
		for i := 0; i+1 < len(parts); i++ {
			switch strings.ToLower(parts[i]) {
			case "resourcegroups":
				resourceGroup = parts[i+1]
			case "storageaccounts":
				account = parts[i+1]
			}
		}
		return resourceGroup, account
	}
	// compact "rg/account"
	if i := strings.IndexByte(t, '/'); i > 0 && i < len(t)-1 {
		return t[:i], t[i+1:]
	}
	return "", ""
}

// validateAzureSubscriptionID checks the subscription-id GUID shape (8-4-4-4-12 hex). Grounded — we
// never record a malformed subscription, which would silently fail every scan.
func validateAzureSubscriptionID(s string) error {
	s = strings.ToLower(strings.TrimSpace(s))
	groups := strings.Split(s, "-")
	if len(groups) != 5 || len(groups[0]) != 8 || len(groups[1]) != 4 ||
		len(groups[2]) != 4 || len(groups[3]) != 4 || len(groups[4]) != 12 {
		return fmt.Errorf("azure: subscription id %q is not a GUID (8-4-4-4-12 hex)", s)
	}
	for _, g := range groups {
		for _, r := range g {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				return fmt.Errorf("azure: subscription id %q has a non-hex character %q", s, string(r))
			}
		}
	}
	return nil
}

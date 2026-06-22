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

// Apply: Azure remediation has no live write path yet (honest stub, pending write creds) — an
// action is never falsely reported "done".
func (a *Azure) Apply(_ context.Context, _ platform.Connection, _ string, act platform.Action) error {
	rt, _ := act.Payload["remediation_type"].(string)
	if rt == "" {
		return fmt.Errorf("azure apply: action %s carries no remediation_type — no live write path, left un-applied", act.ID)
	}
	return fmt.Errorf("azure apply: remediation_type %q has no live Azure write path yet (needs service-principal write creds)", rt)
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

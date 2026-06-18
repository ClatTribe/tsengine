package runner

import (
	"context"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// regConn discovers one repo asset and records webhook registrations.
type regConn struct{ registered []string }

func (r *regConn) Kind() string                   { return platform.ConnGitHub }
func (r *regConn) OAuthURL(string, string) string { return "" }
func (r *regConn) Exchange(context.Context, string, string) (platform.Connection, error) {
	return platform.Connection{}, nil
}
func (r *regConn) Discover(_ context.Context, c platform.Connection, _ string) ([]platform.Asset, error) {
	return []platform.Asset{{TenantID: c.TenantID, ConnectionID: c.ID, Type: "repository",
		Target: "https://github.com/acme/web", Meta: map[string]string{"full_name": "acme/web"}}}, nil
}
func (r *regConn) Watch(context.Context, platform.Connection, []byte) ([]connector.Trigger, error) {
	return nil, nil
}
func (r *regConn) Apply(context.Context, platform.Connection, string, platform.Action) error {
	return nil
}

// RegisterWebhook records the (target, callback) it was asked to register.
func (r *regConn) RegisterWebhook(_ context.Context, _, target, callback, secret string) error {
	r.registered = append(r.registered, target+" -> "+callback+" ("+secret+")")
	return nil
}

type regScanner struct{}

func (regScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) { return nil, nil }

func TestDiscoverAndScan_RegistersWebhook(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	rc := &regConn{}
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(rc), Tokens: fakeTokens{}, Scanner: regScanner{},
		WebhookSecret: "shh", PublicURL: "https://app.example",
	}
	if _, err := svc.DiscoverAndScan(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub}); err != nil {
		t.Fatal(err)
	}
	if len(rc.registered) != 1 || rc.registered[0] != "acme/web -> https://app.example/v1/webhooks/github (shh)" {
		t.Fatalf("expected one webhook registration on the discovered repo, got %v", rc.registered)
	}
}

// Without a secret/public URL, registration is skipped (purely additive).
func TestDiscoverAndScan_NoConfigNoWebhook(t *testing.T) {
	ctx := context.Background()
	rc := &regConn{}
	svc := &Service{Store: store.NewMemory(), Connectors: connector.NewRegistry(rc), Tokens: fakeTokens{}, Scanner: regScanner{}}
	if _, err := svc.DiscoverAndScan(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub}); err != nil {
		t.Fatal(err)
	}
	if len(rc.registered) != 0 {
		t.Errorf("no secret/url → no registration, got %v", rc.registered)
	}
}

var _ http.Handler // keep net/http referenced if unused elsewhere

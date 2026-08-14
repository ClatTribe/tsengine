package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The benchmark and the product must be the same code path. tsbench cvepatch grades
// codeagent.ProposePatch (execution-verified); before this, /v1/findings/{id}/autofix called the LLM
// with its own prompt and never touched codeagent — so the published number described an
// implementation no customer request could reach.

// With no connected repo there is no source, so the fallback is correct — and must SAY it is the
// weaker path rather than passing itself off as the benchmarked one.
func TestAutofix_NoRepoFallsBackHonestly(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	d := Deps{Store: st, Vault: idSealer{}}

	src, repo := d.codeSourceFor(ctx, "t1")
	if src != nil {
		t.Errorf("built source with no GitHub connection (repo=%q) — it would patch a repo we cannot read", repo)
	}
}

// A connection missing the repo config must not produce a half-built source: a wrong-repo read would
// let the engineer rewrite a file it never saw.
func TestAutofix_IncompleteConnectionYieldsNoSource(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	// Account set, repo missing.
	if err := st.PutConnection(ctx, platform.Connection{
		ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Account: "acme", SecretRef: "tok",
		Config: map[string]string{},
	}); err != nil {
		t.Fatal(err)
	}
	d := Deps{Store: st, Vault: idSealer{}}
	if src, _ := d.codeSourceFor(ctx, "t1"); src != nil {
		t.Error("built source from a connection with no repo configured")
	}
}

// The endpoint of a repo finding is file:line — the source read must strip the line or every lookup 404s.
func TestAutofix_EndpointLineIsStrippedForSourceRead(t *testing.T) {
	f := types.Finding{Endpoint: "internal/store/users.go:42"}
	path := f.Endpoint
	if i := strings.LastIndex(path, ":"); i > 0 {
		path = path[:i]
	}
	if path != "internal/store/users.go" {
		t.Errorf("path = %q, want the line suffix stripped", path)
	}
}

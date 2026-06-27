package osint

import (
	"context"
	"strings"
	"testing"
)

func TestParseGitHubCodeSearch_MapsHitsSkipsOwnOrg(t *testing.T) {
	body := `{"total_count":2,"items":[
		{"html_url":"https://github.com/ex-employee/dotfiles/blob/main/.env","repository":{"full_name":"ex-employee/dotfiles"}},
		{"html_url":"https://github.com/acme-corp/internal/blob/main/config.yml","repository":{"full_name":"acme-corp/internal"}}
	]}`
	out := ParseGitHubCodeSearch("AWS access key", []byte(body), map[string]bool{"acme-corp": true})
	if len(out) != 1 {
		t.Fatalf("the org's own repo (acme-corp) must be skipped; want 1 third-party hit, got %d: %+v", len(out), out)
	}
	ls := out[0]
	if ls.Kind != "AWS access key" || ls.Source != "github-search" || !strings.Contains(ls.Location, "ex-employee/dotfiles") {
		t.Errorf("leaked-secret entry wrong: %+v", ls)
	}
}

func TestParseGitHubCodeSearch_MalformedIsEmpty(t *testing.T) {
	if got := ParseGitHubCodeSearch("k", []byte("not json"), nil); got != nil {
		t.Errorf("malformed → no entries, got %+v", got)
	}
}

func TestCollectGitHubLeaks_DedupsAcrossDorksAndFeedsAssess(t *testing.T) {
	// a fake token-authed fetcher: every dork query returns the same leaked file (so dedup must collapse it).
	fetch := func(ctx context.Context, u string) ([]byte, error) {
		if !strings.Contains(u, "api.github.com/search/code") {
			t.Fatalf("unexpected url %q", u)
		}
		return []byte(`{"items":[{"html_url":"https://github.com/x/y/blob/main/.env","repository":{"full_name":"x/y"}}]}`), nil
	}
	snap := CollectGitHubLeaks(context.Background(), "Acme", []string{"acme.com"}, nil, fetch)
	if len(snap.LeakedSecrets) != 1 {
		t.Fatalf("the same file matched by several dorks should dedup to 1, got %d", len(snap.LeakedSecrets))
	}
	// and it flows through the existing detector to an osint::leaked-secret finding
	fs := Assess(snap, Options{})
	var got bool
	for _, f := range fs {
		if f.RuleID == "osint::leaked-secret" {
			got = true
		}
	}
	if !got {
		t.Error("the collected leaked secret should produce an osint::leaked-secret finding")
	}
}

package runner

import (
	"context"
	"log/slog"
	"strings"

	"github.com/ClatTribe/tsengine/internal/identitylinks"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// syncIdentityLinks fetches the person → GitHub join inputs every monitoring pass and stores them
// (internal/identitylinks), so the estate graph can draw identity → code → cloud on every read.
//
// Grounded (§10): with no GitHub connection nothing is asserted about code and the set says so; a
// source that cannot be read (SAML without admin:org, an Okta org with no GitHub app) is NAMED in
// Unread rather than rendered as "no links". Reports whether a set was stored this pass.
func (s *Service) syncIdentityLinks(ctx context.Context, tenantID string) bool {
	if s.Store == nil || s.Tokens == nil || s.IdentityLinkOpts == nil {
		return false
	}
	conns, err := s.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return false
	}
	in := identitylinks.Inputs{TenantID: tenantID, Now: s.now()}
	for _, c := range conns {
		if c.Status != platform.ConnActive {
			continue
		}
		switch c.Kind {
		case platform.ConnGitHub:
			if in.GitHubOrg != "" {
				continue // one organisation per pass; a second connection waits for its own row
			}
			tok, terr := s.Tokens.Resolve(ctx, c)
			if terr != nil || tok == "" {
				continue
			}
			in.GitHubOrg, in.GitHubToken = c.Account, tok
		case platform.ConnOkta:
			if tok, terr := s.Tokens.Resolve(ctx, c); terr == nil && tok != "" {
				in.OktaToken = tok
			}
		}
	}
	if in.GitHubOrg == "" && in.OktaToken == "" {
		return false // nothing connected that could assert a link — not a set worth storing
	}
	if assets, err := s.Store.ListAssets(ctx, tenantID); err == nil {
		for _, a := range assets {
			if a.Type != "repository" {
				continue
			}
			full := a.Meta["full_name"]
			if full == "" {
				full = a.Target
			}
			if strings.Count(full, "/") == 1 {
				in.Repos = append(in.Repos, full)
			}
		}
	}
	set := identitylinks.Fetch(ctx, *s.IdentityLinkOpts, in)
	if err := s.Store.PutIdentityLinks(ctx, set); err != nil {
		slog.Warn("[scan] identity links not stored", "tenant", tenantID, "err", err.Error())
		return false
	}
	slog.Info("[scan] identity links fetched", "tenant", tenantID, "links", len(set.Links), "controls", len(set.Controls), "unread", len(set.Unread))
	return true
}

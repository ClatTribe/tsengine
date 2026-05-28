package hooks

import (
	"regexp"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// SurfacePriority implements hook 3 of CLAUDE.md §11. It annotates each
// finding with a 0-100 reachability score — how exposed / important the
// surface this finding sits on is. The L2 lead uses this to prioritize;
// the security engineer sees it as a triage hint.
//
// This is an annotation-only hook: it never drops or mutates severity.
type SurfacePriority struct{}

// NewSurfacePriority constructs the hook.
func NewSurfacePriority() *SurfacePriority { return &SurfacePriority{} }

func (*SurfacePriority) Name() string { return "surface_priority" }

var (
	// High-value surfaces: auth, admin, API, payment endpoints.
	highValueSurface = regexp.MustCompile(`(?i)/(login|signin|admin|api|oauth|token|payment|checkout|account|user|graphql)(/|\?|$|:)`)
	// Low-value surfaces: static, docs, health.
	lowValueSurface = regexp.MustCompile(`(?i)/(static|assets|docs|favicon|robots\.txt|health|metrics)(/|\?|$)`)
)

// Apply scores the finding's endpoint.
func (h *SurfacePriority) Apply(f types.Finding) (types.Finding, []types.AuditEntry, bool) {
	score, reason := scoreSurface(f.Endpoint)
	f.SurfacePriority = &types.SurfacePriority{Score: score, Reason: reason}
	return f, nil, true
}

func scoreSurface(endpoint string) (int, string) {
	switch {
	case endpoint == "":
		return 30, "no endpoint context"
	case highValueSurface.MatchString(endpoint):
		return 85, "high-value surface (auth/admin/api/payment)"
	case lowValueSurface.MatchString(endpoint):
		return 15, "low-value surface (static/docs/health)"
	default:
		return 50, "standard application surface"
	}
}

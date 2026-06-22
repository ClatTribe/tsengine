package registrywatch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GHCR lists a GitHub user/org's container images from the GitHub Container Registry — the second
// registry source after Docker Hub, and a natural fit for the many SMBs already on GitHub (GHCR is
// free with every account). It reuses the GitHub token (a `read:packages` scope), so a tenant that
// connected GitHub gets container scan-on-push with no new credential. Like DockerHub, ListImages
// returns []Image for Reconcile (only new/re-pushed digests get scanned).
//
// The live fetch is the credential-gated half (owner + token); the digest-diff + dispatch are the
// deterministic halves already shipped (§13 — this adds a source, not a new scanner).
type GHCR struct {
	Owner     string       // the org or user whose container packages to enumerate
	IsUser    bool         // true → /users/{owner}/packages; false (default) → /orgs/{owner}/packages
	Token     string       // GitHub token with read:packages
	BaseURL   string       // default https://api.github.com
	MaxImages int          // safety cap on total tags returned (default 1000); 0 → default
	HTTP      *http.Client // overridable for tests
}

// NewGHCR builds the lister for an org (set IsUser for a personal account).
func NewGHCR(owner, token string) *GHCR {
	return &GHCR{Owner: owner, Token: token, BaseURL: "https://api.github.com", MaxImages: 1000, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (g *GHCR) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return http.DefaultClient
}

func (g *GHCR) base() string {
	if g.BaseURL == "" {
		return "https://api.github.com"
	}
	return strings.TrimRight(g.BaseURL, "/")
}

func (g *GHCR) maxImages() int {
	if g.MaxImages <= 0 {
		return 1000
	}
	return g.MaxImages
}

func (g *GHCR) ownerScope() string {
	if g.IsUser {
		return "/users/"
	}
	return "/orgs/"
}

type ghcrPackage struct {
	Name string `json:"name"`
}

type ghcrVersion struct {
	Name     string `json:"name"` // the image digest, "sha256:..."
	Metadata struct {
		Container struct {
			Tags []string `json:"tags"`
		} `json:"container"`
	} `json:"metadata"`
}

func (g *GHCR) get(ctx context.Context, rawURL string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("ghcr: GET %s: HTTP %d: %s", rawURL, resp.StatusCode, b)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(into)
}

// ListImages enumerates the owner's container packages and each package's tagged versions into
// []Image. Both lists are page-paginated (bounded), and the total is capped at MaxImages so a huge
// registry can't run away. Each (package, tag) → Image{Repo:"ghcr.io/<owner>/<pkg>", Tag, Digest};
// an untagged version (an intermediate layer) is skipped — only deployable, tagged images are scanned.
func (g *GHCR) ListImages(ctx context.Context) ([]Image, error) {
	if g.Owner == "" {
		return nil, fmt.Errorf("ghcr: owner required")
	}
	var images []Image
	for page := 1; page <= 50; page++ {
		var pkgs []ghcrPackage
		u := fmt.Sprintf("%s%s%s/packages?package_type=container&per_page=100&page=%d",
			g.base(), g.ownerScope(), url.PathEscape(g.Owner), page)
		if err := g.get(ctx, u, &pkgs); err != nil {
			return nil, err
		}
		for _, p := range pkgs {
			if p.Name == "" {
				continue
			}
			imgs, err := g.listVersions(ctx, p.Name)
			if err != nil {
				return nil, err
			}
			images = append(images, imgs...)
			if len(images) >= g.maxImages() {
				return images[:g.maxImages()], nil
			}
		}
		if len(pkgs) < 100 {
			break // last page
		}
	}
	return images, nil
}

func (g *GHCR) listVersions(ctx context.Context, pkg string) ([]Image, error) {
	repo := "ghcr.io/" + g.Owner + "/" + pkg
	var out []Image
	for page := 1; page <= 50; page++ {
		var versions []ghcrVersion
		u := fmt.Sprintf("%s%s%s/packages/container/%s/versions?per_page=100&page=%d",
			g.base(), g.ownerScope(), url.PathEscape(g.Owner), url.PathEscape(pkg), page)
		if err := g.get(ctx, u, &versions); err != nil {
			return nil, err
		}
		for _, v := range versions {
			if v.Name == "" {
				continue
			}
			for _, tag := range v.Metadata.Container.Tags {
				if tag == "" {
					continue
				}
				out = append(out, Image{Repo: repo, Tag: tag, Digest: v.Name})
			}
		}
		if len(versions) < 100 {
			break
		}
	}
	return out, nil
}

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

// DockerHub lists a namespace's images from Docker Hub — the built-in source half that was the
// container_image gap: until now an SMB had to hand-assemble the image list to POST at
// /v1/registry/reconcile. DockerHub.ListImages walks the org/user's repositories and their tags
// into []Image, which feeds Reconcile (scan-on-push: only new/re-pushed digests get scanned).
//
// Public repos work token-less; a Personal Access Token (Bearer) unlocks private repos. The live
// fetch is the credential-gated half (namespace + optional token); the digest-diff + dispatch are
// the deterministic halves already shipped (§13 — this adds a source, not a new scanner).
type DockerHub struct {
	Namespace string       // the org/user whose repositories to enumerate (e.g. "acmecorp")
	Token     string       // optional PAT for private repos; "" → public repos only
	BaseURL   string       // default https://hub.docker.com
	MaxImages int          // safety cap on total tags returned (default 1000); 0 → default
	HTTP      *http.Client // overridable for tests
}

// NewDockerHub builds the lister for a namespace.
func NewDockerHub(namespace, token string) *DockerHub {
	return &DockerHub{Namespace: namespace, Token: token, BaseURL: "https://hub.docker.com", MaxImages: 1000, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (d *DockerHub) client() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return http.DefaultClient
}

func (d *DockerHub) base() string {
	if d.BaseURL == "" {
		return "https://hub.docker.com"
	}
	return strings.TrimRight(d.BaseURL, "/")
}

func (d *DockerHub) maxImages() int {
	if d.MaxImages <= 0 {
		return 1000
	}
	return d.MaxImages
}

type dhRepoPage struct {
	Next    string `json:"next"`
	Results []struct {
		Name string `json:"name"`
	} `json:"results"`
}

type dhTagPage struct {
	Next    string `json:"next"`
	Results []struct {
		Name   string `json:"name"`
		Digest string `json:"digest"` // manifest-list digest (newer API); may be empty
		Images []struct {
			Digest string `json:"digest"`
		} `json:"images"`
	} `json:"results"`
}

func (d *DockerHub) get(ctx context.Context, rawURL string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if d.Token != "" {
		req.Header.Set("Authorization", "Bearer "+d.Token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("dockerhub: GET %s: HTTP %d: %s", rawURL, resp.StatusCode, b)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(into)
}

// ListImages enumerates the namespace's repositories and each repo's tags into []Image. Repos and
// tags are both paginated via the API's `next` cursor (bounded); the total is capped at MaxImages
// so a huge registry can't run away. Each tag → Image{Repo: "<ns>/<repo>", Tag, Digest}; a tag with
// no resolvable digest is skipped (Reconcile can't pin/diff it anyway). Repo is the Docker Hub ref
// form ("<ns>/<repo>") that the container scanner pulls.
func (d *DockerHub) ListImages(ctx context.Context) ([]Image, error) {
	if d.Namespace == "" {
		return nil, fmt.Errorf("dockerhub: namespace required")
	}
	var images []Image
	repoURL := d.base() + "/v2/repositories/" + url.PathEscape(d.Namespace) + "/?page_size=100"
	for page := 0; repoURL != "" && page < 50; page++ {
		var rp dhRepoPage
		if err := d.get(ctx, repoURL, &rp); err != nil {
			return nil, err
		}
		for _, repo := range rp.Results {
			if repo.Name == "" {
				continue
			}
			full := d.Namespace + "/" + repo.Name
			imgs, err := d.listTags(ctx, full, repo.Name)
			if err != nil {
				return nil, err
			}
			images = append(images, imgs...)
			if len(images) >= d.maxImages() {
				return images[:d.maxImages()], nil
			}
		}
		repoURL = rp.Next
	}
	return images, nil
}

func (d *DockerHub) listTags(ctx context.Context, fullRepo, repoName string) ([]Image, error) {
	var out []Image
	tagURL := d.base() + "/v2/repositories/" + url.PathEscape(d.Namespace) + "/" + url.PathEscape(repoName) + "/tags?page_size=100"
	for page := 0; tagURL != "" && page < 50; page++ {
		var tp dhTagPage
		if err := d.get(ctx, tagURL, &tp); err != nil {
			return nil, err
		}
		for _, t := range tp.Results {
			digest := t.Digest
			if digest == "" && len(t.Images) > 0 {
				digest = t.Images[0].Digest
			}
			if t.Name == "" || digest == "" {
				continue // unidentifiable tag — Reconcile would skip it anyway
			}
			out = append(out, Image{Repo: fullRepo, Tag: t.Name, Digest: digest})
		}
		tagURL = tp.Next
	}
	return out, nil
}

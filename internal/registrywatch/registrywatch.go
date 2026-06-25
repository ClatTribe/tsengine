// Package registrywatch is the container-registry auto-watch core (ADR 0010 Phase 4) — the
// "scan on push" capability that closes the container_image gap vs Aikido/Snyk. Today we scan a
// GIVEN image; competitors connect your registry (ECR/GHCR/Docker Hub) and scan every image as
// it's pushed. The efficient way to do that is a digest diff: scan only the images that are new
// or whose digest changed (a fresh push), never re-scan the whole registry every cycle.
//
// This is the deterministic, offline-testable reconciler (the sibling of detect.Reconcile for
// incidents). The live registry listing (registry API → current digests) is the gated connector
// half; the scan dispatch routes to our existing trivy/grype container scan (§13 — no new tool).
package registrywatch

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Image is one tag in a registry at a point in time. Digest is the immutable content id — the
// same ref:tag can point at a new digest after a re-push, which is exactly what we must catch.
type Image struct {
	Repo   string `json:"repo"`   // e.g. 111122223333.dkr.ecr.us-east-1.amazonaws.com/api
	Tag    string `json:"tag"`    // e.g. 1.2.0 / latest
	Digest string `json:"digest"` // sha256:...
}

// Ref is the mutable name (repo:tag); Pinned is the immutable repo@digest the scanner runs on.
func (i Image) Ref() string    { return i.Repo + ":" + i.Tag }
func (i Image) Pinned() string { return i.Repo + "@" + i.Digest }

// mutableTags are well-known rolling tags whose digest drifts over time — a clean scan of
// repo:latest silently goes stale when latest is re-pushed. The conservative, FP-safe set: only
// unambiguously-rolling names (a semver / date / git-sha tag is treated as immutable, never flagged).
var mutableTags = map[string]bool{
	"latest": true, "stable": true, "main": true, "master": true, "dev": true, "develop": true,
	"edge": true, "nightly": true, "prod": true, "production": true, "canary": true,
	"release": true, "current": true, "testing": true,
}

// MutableTag reports whether the image is referenced by a rolling/mutable tag (so its scanned
// digest can change under you). A bare/empty tag is an implicit :latest. Anything not in the
// well-known rolling set is treated as immutable (FP-safe — we don't guess about custom tags).
func (i Image) MutableTag() bool {
	t := strings.ToLower(strings.TrimSpace(i.Tag))
	return t == "" || mutableTags[t]
}

// Result is the reconcile outcome: which images to (re)scan + the seen-state to persist.
type Result struct {
	ToScan    []Image           `json:"to_scan"`
	New       int               `json:"new"`       // a ref not seen before
	Updated   int               `json:"updated"`   // a known ref with a new digest (a re-push)
	Unchanged int               `json:"unchanged"` // same ref, same digest → skipped
	NextSeen  map[string]string `json:"-"`         // ref → digest, persist for the next reconcile
}

// Reconcile diffs the registry's current images against the last-seen digests (ref → digest) and
// returns ONLY the images that are new or whose digest changed — so scan-on-push scans what
// changed, not the whole registry. NextSeen reflects the CURRENT registry (deleted tags fall
// out). Deterministic: ToScan is sorted by ref. An image with an empty digest is skipped (we
// can't pin/diff it — never scan an unidentifiable image, and never falsely mark it seen).
func Reconcile(current []Image, seen map[string]string) Result {
	r := Result{NextSeen: map[string]string{}}
	for _, img := range current {
		if img.Digest == "" || img.Repo == "" {
			continue
		}
		ref := img.Ref()
		r.NextSeen[ref] = img.Digest
		prev, known := seen[ref]
		switch {
		case !known:
			r.New++
			r.ToScan = append(r.ToScan, img)
		case prev != img.Digest:
			r.Updated++
			r.ToScan = append(r.ToScan, img)
		default:
			r.Unchanged++
		}
	}
	sort.Slice(r.ToScan, func(i, j int) bool { return r.ToScan[i].Ref() < r.ToScan[j].Ref() })
	return r
}

// MutableTagFindings flags every image deployed by a mutable/rolling tag — a container
// supply-chain hygiene gap (the scanned digest can change under you, so a past clean scan
// silently goes stale). Grounded: each finding cites the exact repo:tag and the digest it
// currently resolves to. FP-safe: an image referenced by an immutable tag (semver/date/sha)
// yields nothing. Severity is low (advisory best-practice, not an active vuln); the fix is to
// deploy by digest (Pinned()). Deterministic + sorted.
func MutableTagFindings(images []Image) []types.Finding {
	var out []types.Finding
	for _, img := range images {
		if img.Repo == "" || !img.MutableTag() {
			continue
		}
		desc := "Image " + img.Ref() + " is deployed by a mutable tag; its digest can change on the next push, so a clean scan can silently go stale. Pin to the digest instead"
		if img.Digest != "" {
			desc += " (currently " + img.Pinned() + ")"
		}
		desc += "."
		out = append(out, types.Finding{
			RuleID: "registrywatch::mutable-tag", Tool: "registrywatch",
			Severity: types.SeverityLow, CWE: []string{"CWE-494"}, // download of code without integrity check
			Endpoint: img.Ref(), Title: "Container deployed by a mutable tag: " + img.Ref(),
			Description:     desc,
			MITRETechniques: []string{"T1195.001"}, // supply-chain compromise of software dependencies
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
	return out
}

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

import "sort"

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

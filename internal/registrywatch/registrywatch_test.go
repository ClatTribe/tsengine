package registrywatch

import "testing"

func img(repo, tag, digest string) Image { return Image{Repo: repo, Tag: tag, Digest: digest} }

func TestReconcile_ScansOnlyNewOrChanged(t *testing.T) {
	current := []Image{
		img("acme/api", "1.2", "sha256:aaa"),    // unchanged
		img("acme/api", "latest", "sha256:bbb"), // updated (re-push)
		img("acme/web", "3.0", "sha256:ccc"),    // new
	}
	seen := map[string]string{
		"acme/api:1.2":    "sha256:aaa", // same digest → unchanged
		"acme/api:latest": "sha256:OLD", // different digest → updated
		// acme/web:3.0 absent → new
	}
	r := Reconcile(current, seen)

	if r.New != 1 || r.Updated != 1 || r.Unchanged != 1 {
		t.Fatalf("want new=1 updated=1 unchanged=1, got new=%d updated=%d unchanged=%d", r.New, r.Updated, r.Unchanged)
	}
	if len(r.ToScan) != 2 {
		t.Fatalf("only the new + updated images should scan, got %d", len(r.ToScan))
	}
	// Sorted by ref; the unchanged image is NOT in the plan.
	for _, s := range r.ToScan {
		if s.Ref() == "acme/api:1.2" {
			t.Error("an unchanged image must not be re-scanned")
		}
	}
	// The scanner pins by digest, not the mutable tag.
	if r.ToScan[0].Pinned() != "acme/api@sha256:bbb" {
		t.Errorf("scan target should be repo@digest, got %s", r.ToScan[0].Pinned())
	}
	// NextSeen reflects the current registry.
	if r.NextSeen["acme/api:latest"] != "sha256:bbb" || r.NextSeen["acme/web:3.0"] != "sha256:ccc" {
		t.Errorf("NextSeen should reflect current digests, got %v", r.NextSeen)
	}
}

func TestReconcile_FirstRunScansAll(t *testing.T) {
	current := []Image{img("a/x", "1", "sha256:1"), img("a/y", "1", "sha256:2")}
	r := Reconcile(current, nil) // no prior state
	if r.New != 2 || len(r.ToScan) != 2 {
		t.Errorf("first reconcile scans everything, got new=%d toScan=%d", r.New, len(r.ToScan))
	}
}

func TestReconcile_SkipsUnidentifiableImages(t *testing.T) {
	// An image with no digest can't be pinned/diffed → skipped, and NOT marked seen.
	r := Reconcile([]Image{img("a/x", "1", ""), img("", "1", "sha256:z")}, nil)
	if len(r.ToScan) != 0 || r.New != 0 {
		t.Errorf("images with no digest/repo must be skipped, got %+v", r)
	}
	if len(r.NextSeen) != 0 {
		t.Error("an unidentifiable image must not be recorded as seen")
	}
}

func TestReconcile_Idempotent(t *testing.T) {
	current := []Image{img("a/x", "1", "sha256:1")}
	first := Reconcile(current, nil)
	// Feeding NextSeen back with the same registry → nothing to scan (steady state).
	second := Reconcile(current, first.NextSeen)
	if len(second.ToScan) != 0 || second.Unchanged != 1 {
		t.Errorf("a steady registry should produce no rescans, got %+v", second)
	}
}

func TestMutableTagFindings(t *testing.T) {
	imgs := []Image{
		{Repo: "acme/api", Tag: "latest", Digest: "sha256:aaa"}, // mutable
		{Repo: "acme/web", Tag: "", Digest: "sha256:bbb"},       // implicit :latest → mutable
		{Repo: "acme/job", Tag: "STABLE", Digest: "sha256:ccc"}, // case-insensitive mutable
		{Repo: "acme/db", Tag: "1.2.3", Digest: "sha256:ddd"},   // semver → immutable, no finding
		{Repo: "acme/cache", Tag: "2026-06-22", Digest: ""},     // date → immutable
		{Repo: "", Tag: "latest"},                               // no repo → skipped
	}
	fs := MutableTagFindings(imgs)
	if len(fs) != 3 {
		t.Fatalf("expected 3 mutable-tag findings (latest, bare, STABLE), got %d", len(fs))
	}
	for _, f := range fs {
		if f.RuleID != "registrywatch::mutable-tag" || f.Severity != "low" || f.CWE[0] != "CWE-494" {
			t.Errorf("unexpected finding shape: %+v", f)
		}
	}
	// Sorted by endpoint (deterministic).
	if fs[0].Endpoint != "acme/api:latest" {
		t.Errorf("findings should be sorted by endpoint, got first=%s", fs[0].Endpoint)
	}

	// FP-safety: a registry of only immutable (semver/date/sha) tags yields nothing.
	clean := []Image{
		{Repo: "acme/api", Tag: "1.0.0", Digest: "sha256:x"},
		{Repo: "acme/web", Tag: "v2.3.4-rc1", Digest: "sha256:y"},
		{Repo: "acme/db", Tag: "20260622", Digest: "sha256:z"},
	}
	if fs := MutableTagFindings(clean); len(fs) != 0 {
		t.Errorf("immutable tags must yield no findings (FP), got %d", len(fs))
	}
}

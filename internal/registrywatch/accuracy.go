package registrywatch

// This file is the mutable-tag accuracy harness — a labeled corpus of image refs + a scorer that
// MEASURES MutableTag's precision/recall (the rolling-tag taxonomy from the mutable-tag finding).
// Same sensitivity↔specificity discipline as the per-asset benches (CLAUDE.md §14.1.1).

// LabeledImage is one image ref with its ground-truth: is its tag mutable (rolling, digest can
// drift) or immutable (pin-equivalent)?
type LabeledImage struct {
	Image   Image
	Mutable bool
}

// TagScore is the confusion matrix over the corpus.
type TagScore struct{ TP, FP, FN, TN int }

// Recall = TP / (TP + FN) — of the truly-mutable tags, how many were flagged (FN axis).
func (s TagScore) Recall() float64 {
	if s.TP+s.FN == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FN)
}

// Precision = TP / (TP + FP) — of the flagged tags, how many were truly mutable (FP axis).
func (s TagScore) Precision() float64 {
	if s.TP+s.FP == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

// ScoreTags runs MutableTag over each labeled image and tallies the confusion matrix.
func ScoreTags(cases []LabeledImage) TagScore {
	var s TagScore
	for _, c := range cases {
		switch got := c.Image.MutableTag(); {
		case c.Mutable && got:
			s.TP++
		case c.Mutable && !got:
			s.FN++
		case !c.Mutable && got:
			s.FP++
		default:
			s.TN++
		}
	}
	return s
}

// TagCorpus is the built-in labeled corpus: rolling/mutable tags (must flag → recall) + immutable
// tags — semver, prefixed-semver, date, git-sha, a custom build id (must NOT flag → precision).
func TagCorpus() []LabeledImage {
	mut := []string{"latest", "", "STABLE", "main", "master", "dev", "develop", "edge", "nightly", "prod", "production", "canary", "release", "testing"}
	imm := []string{"1.2.3", "v2.3.4", "1.2.3-rc1", "2026-06-22", "20260622", "sha-9f8e7d6", "git-abc1234", "build-4815", "20.04"}
	out := make([]LabeledImage, 0, len(mut)+len(imm))
	for _, tag := range mut {
		out = append(out, LabeledImage{Image: Image{Repo: "acme/app", Tag: tag, Digest: "sha256:x"}, Mutable: true})
	}
	for _, tag := range imm {
		out = append(out, LabeledImage{Image: Image{Repo: "acme/app", Tag: tag, Digest: "sha256:x"}, Mutable: false})
	}
	return out
}

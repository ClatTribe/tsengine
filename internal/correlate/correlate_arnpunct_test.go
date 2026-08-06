package correlate

import "testing"

// An ARN that closes a sentence must extract to the SAME string as one written bare. It previously
// swallowed the trailing '.', producing a different entity than the cloud-side finding carried — so
// the shared identifier never matched and the code→cloud bridge silently vanished. That is the
// cross-surface wedge's core join failing on a full stop, with nothing logged.
func TestARNRegex_StopsBeforeTrailingPunctuation(t *testing.T) {
	const want = "arn:aws:iam::123456789012:role/app-runner"
	for name, in := range map[string]string{
		"sentence end": "assumed by " + want + ".",
		"comma":        "grants " + want + ", plus more",
		"semicolon":    "role " + want + "; see policy",
		"parenthesis":  "(" + want + ")",
		"bare":         want,
		"trailing ws":  want + "   ",
	} {
		if got := arnRe.FindString(in); got != want {
			t.Errorf("%s: extracted %q, want %q — a mismatched entity drops the bridge", name, got, want)
		}
	}
}

// Legitimate interior dots and slashes must survive — the fix must not truncate a real resource path.
func TestARNRegex_KeepsInteriorDotsAndSlashes(t *testing.T) {
	// NB: S3 ARNs (arn:aws:s3:::bucket) carry no account id and are matched by bucketRe, not arnRe —
	// so they are deliberately absent here.
	for _, want := range []string{
		"arn:aws:iam::123456789012:role/service-role/my.app.runner",
		"arn:aws:lambda:us-east-1:123456789012:function:my-fn",
		"arn:aws:iam::123456789012:role/*", // a wildcard is a valid final character
	} {
		if got := arnRe.FindString(want + "."); got != want {
			t.Errorf("extracted %q, want %q", got, want)
		}
	}
}

// End to end: the same role written with and without a trailing period must correlate as one entity.
func TestEntityExtraction_SentenceEndARNStillBridges(t *testing.T) {
	code := extractEntities(Finding{ID: "f1", Title: "hardcoded credential",
		Description: "assumes arn:aws:iam::123456789012:role/app-runner."})
	cloud := extractEntities(Finding{ID: "f2", Title: "over-permissioned role",
		Description: "arn:aws:iam::123456789012:role/app-runner allows s3:*"})

	shared := false
	for _, a := range code {
		for _, b := range cloud {
			if a.Kind == b.Kind && a.Value == b.Value {
				shared = true
			}
		}
	}
	if !shared {
		t.Fatalf("the same ARN must bridge across surfaces; code=%v cloud=%v", code, cloud)
	}
}

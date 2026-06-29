package sandbox

import "testing"

func TestResolveImages_FallbackWhenPentestUnset(t *testing.T) {
	// Single-image deploy (TSENGINE_PENTEST_SANDBOX_IMAGE unset) → pentest falls back to scan, unchanged.
	got := ResolveImages("tsengine/sandbox:0.1.0", "")
	if got.Scan != "tsengine/sandbox:0.1.0" {
		t.Errorf("scan = %q, want tsengine/sandbox:0.1.0", got.Scan)
	}
	if got.Pentest != got.Scan {
		t.Errorf("pentest must fall back to scan when unset, got %q", got.Pentest)
	}
}

func TestResolveImages_SplitWhenBothSet(t *testing.T) {
	// Both set (and trimmed) → the two-image split is honored.
	got := ResolveImages("  tsengine/sandbox:0.1.0 ", " tsengine/pentest-sandbox:0.1.0  ")
	if got.Scan != "tsengine/sandbox:0.1.0" {
		t.Errorf("scan = %q", got.Scan)
	}
	if got.Pentest != "tsengine/pentest-sandbox:0.1.0" {
		t.Errorf("pentest = %q, want the split image", got.Pentest)
	}
}

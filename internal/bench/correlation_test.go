package bench

import "testing"

func TestCorrelationCoverage_CrossSurfaceChains(t *testing.T) {
	r := RunCorrelationCoverage()
	t.Logf("chains: found=%d/%d total=%d spurious=%d missed=%v | unified=%d ok=%v",
		r.FoundChains, r.ExpectedChains, r.TotalChains, r.Spurious, r.Missed, r.UnifiedIssues, r.UnifiedOK)
	if !r.Pass() {
		t.Errorf("correlation not a clean sweep: missed=%v spurious=%d unifiedOK=%v", r.Missed, r.Spurious, r.UnifiedOK)
	}
}

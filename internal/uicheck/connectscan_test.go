package uicheck

import (
	"strings"
	"testing"
)

// connectscan_test.go guards the READER half of the post-connect first scan.
//
// The OAuth callback queues the discover+scan as a "connect" job and lands the browser on /assets
// with the job id. The job carries three facts a person needs and a green tick would hide: that it
// FAILED (with the platform's reason — an empty findings list on a security product otherwise reads
// as "nothing wrong"), that it was PARTIAL (one repository did not scan while the others did), and
// that it is still RUNNING. Each check reads the real source and FAILS rather than skips when the
// file moves (§14.2 rule 6).
func TestConnectBannerRendersFailureAndPartialPass(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "assets", "connect-scan-status.tsx"))
	for _, want := range []struct{ needle, why string }{
		{`status === "failed"`, "a failed first scan must render as failed, not as an empty estate"},
		{`job.error`, "the failure must carry the platform's real reason"},
		{`result?.warning`, "a partial pass (one asset failed, the rest scanned) must be visible, not folded into success"},
		{`result?.assets_scanned`, "a finished scan must say how many assets it covered"},
		{`animate-spin`, "a running scan must look like one"},
		{`router.refresh()`, "the server-rendered asset list must catch up when the job finishes"},
	} {
		if !strings.Contains(src, want.needle) {
			t.Errorf("connect-scan-status.tsx no longer contains %q — %s", want.needle, want.why)
		}
	}
}

// The assets page must hand the job id to the poller AND still count a failed "connect" job as a
// failed scan in its existing failed-scan banner — the callback's job is a scan run like any other.
func TestAssetsPageWiresTheConnectJob(t *testing.T) {
	src := stripComments(frontendFile(t, "app", "(app)", "assets", "page.tsx"))
	if !strings.Contains(src, "<ConnectScanStatus") || !strings.Contains(src, "jobId={job}") {
		t.Errorf("assets/page.tsx must render ConnectScanStatus with the job id from the callback redirect")
	}
	if !strings.Contains(src, `j.kind === "connect"`) {
		t.Errorf("assets/page.tsx must treat a failed \"connect\" job as a failed scan, not only \"rescan\"")
	}
}

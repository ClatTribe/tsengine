package uicheck

import (
	"strings"
	"testing"
)

// The customer's own alert channels are configured AND exercised on the settings page. Two halves are
// guarded: every channel the server knows about is rendered (a channel the API accepts and the page
// never offers is one nobody can set up), and a failed test is shown as a failure with the
// destination's own error — a test result rendered as "sent" when the destination refused it is a
// channel the customer believes is watching and is not. FAILS rather than skips when the file moves
// (§14.2 rule 6).
func TestNotificationChannelsAreConfigurableAndTestable(t *testing.T) {
	src := stripComments(frontendFile(t, "components", "settings", "notification-channels-control.tsx"))
	for _, ch := range []string{`id: "slack"`, `id: "teams"`, `id: "discord"`, `id: "pagerduty"`, `id: "webhook"`} {
		if !strings.Contains(src, ch) {
			t.Errorf("the settings page does not offer the %s channel the API accepts", ch)
		}
	}
	if !strings.Contains(src, "testNotifyChannel(def.id)") {
		t.Fatal("a configured channel has no test — saved and never exercised looks exactly like working")
	}
	if !strings.Contains(src, "did not accept the test") || !strings.Contains(src, "test.error") {
		t.Error("a refused test must be rendered as a failure with the destination's error")
	}
	if !strings.Contains(src, "This pages your on-call rotation") {
		t.Error("a PagerDuty test wakes a real person and must be confirmed first")
	}
	page := stripComments(frontendFile(t, "app", "(app)", "settings", "page.tsx"))
	if !strings.Contains(page, "<NotificationChannelsControl initial={notify} />") {
		t.Fatal("the settings page no longer renders the notification channels control")
	}
}

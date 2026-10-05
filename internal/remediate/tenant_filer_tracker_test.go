package remediate

import (
	"context"
	"errors"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Reading the same key from a DIFFERENT Jira site would read a different issue and report its status
// as this one's. A moved destination must refuse, not guess.
func TestTrackerFor_RefusesWhenTheDestinationMoved(t *testing.T) {
	tf := TenantFiler{Resolve: func(context.Context, string) (string, string, string, string, bool) {
		return "https://new-site.atlassian.net", "e", "tok", "SEC", true
	}}
	ref := platform.TicketRef{System: "jira", Key: "SEC-1", Destination: "tenant", URL: "https://old-site.atlassian.net/browse/SEC-1"}
	if _, err := tf.TrackerFor(context.Background(), "t1", ref); !errors.Is(err, ErrDestinationMoved) {
		t.Fatalf("want ErrDestinationMoved, got %v", err)
	}
	ref.URL = "https://new-site.atlassian.net/browse/SEC-1"
	if _, err := tf.TrackerFor(context.Background(), "t1", ref); err != nil {
		t.Fatalf("same site must resolve: %v", err)
	}
}

package runner

import (
	"context"
	"log/slog"
	"sync"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// pollevents.go: the fast clock for the event sources.
//
// The CloudTrail and identity-provider readers ran only inside the full monitoring pass, which runs every
// 12 hours by default. So the product read a root console login, a public bucket being created or a
// password spray within minutes of it appearing in the log — and then waited up to half a day to read the
// log. An "always-on" agent that learns of a public bucket the next morning is not always on.
//
// PollEvents reads just those sources on their own short interval and opens incidents straight away
// (Detector.OpenFor — open-only, never a resolve sweep, because a poll is not an authoritative census and
// an event is closed by a person, not by absence). The full pass still runs them too; both share the
// per-source cursors, and event findings carry content-derived ids, so whichever reads an event first
// reports it once.

// eventLocks serialises event-source reads per tenant, so the poller and the full pass never read and
// advance the same cursors at the same moment (each writes the tenant record back).
var eventLocks sync.Map // tenantID → *sync.Mutex

func lockEvents(tenantID string) func() {
	m, _ := eventLocks.LoadOrStore(tenantID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// EventPollResult is what one poll did.
type EventPollResult struct {
	CloudRead    bool `json:"cloud_read"`
	IdentityRead bool `json:"identity_read"`
	Findings     int  `json:"findings"`
	Opened       int  `json:"incidents_opened"`
}

// PollEvents reads the tenant's event sources and opens incidents for what they found. A halted tenant
// (the kill-switch) is not read: the switch pauses scanning, and reading the customer's logs is scanning.
func (s *Service) PollEvents(ctx context.Context, tenantID string) EventPollResult {
	var res EventPollResult
	if s.halted(ctx, tenantID) {
		return res
	}
	cdr, cloudRan := s.SyncCloudEvents(ctx, tenantID)
	idl, idRan := s.SyncIdentityLogs(ctx, tenantID)
	res.CloudRead, res.IdentityRead = cloudRan, idRan
	found := append(append([]types.Finding{}, cdr.Findings...), idl.Findings...)
	res.Findings = len(found)
	if s.Detector == nil || len(found) == 0 {
		return res
	}
	r, err := s.Detector.OpenFor(ctx, tenantID, found, nil)
	if err != nil {
		slog.Warn("[events] incidents not opened", "tenant", tenantID, "err", err.Error())
		return res
	}
	res.Opened = len(r.Opened)
	return res
}

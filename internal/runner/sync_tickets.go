package runner

import (
	"context"
	"log/slog"

	"github.com/ClatTribe/tsengine/internal/ticketsync"
)

// syncTickets reads the tenant's delivered tickets back and records the tracker's view (internal/
// ticketsync). Best-effort: a tracker outage never fails a pass. Returns what it did, for the poll's log.
//
// PERSISTENCE WRITES ONLY THE TICKET. The sync works from a list read moments earlier, and the full pass,
// the desk and the event poll all write actions; writing the whole stale copy back could undo a
// verification the pass just recorded. So each changed action is re-read and only its Ticket replaced.
func (s *Service) syncTickets(ctx context.Context, tenantID string) ticketsync.Result {
	if s.TicketTracker == nil || s.Store == nil || s.halted(ctx, tenantID) {
		return ticketsync.Result{}
	}
	acts, err := s.Store.ListActions(ctx, tenantID)
	if err != nil {
		return ticketsync.Result{}
	}
	changed, res := ticketsync.Sync(ctx, acts, s.TicketTracker, s.now(), ticketsync.Options{Comments: true})
	for _, c := range changed {
		fresh, gerr := s.Store.GetAction(ctx, tenantID, c.ID)
		if gerr != nil {
			continue
		}
		fresh.Ticket = c.Ticket
		if perr := s.Store.PutAction(ctx, fresh); perr != nil {
			slog.Warn("ticket sync: not persisted", "tenant", tenantID, "action", c.ID, "err", perr.Error())
		}
	}
	if res.NewlyResolved > 0 || res.ClosedStillPresent > 0 || res.Commented > 0 {
		slog.Info("ticket sync", "tenant", tenantID, "read", res.Read, "resolved", res.NewlyResolved,
			"closed_still_present", res.ClosedStillPresent, "commented", res.Commented, "read_failed", res.ReadFailed)
	}
	return res
}

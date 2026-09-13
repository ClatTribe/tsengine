package runner

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudcdr"
	"github.com/ClatTribe/tsengine/internal/l15"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// CloudEventWindow is how far back the first read of a connection looks; CloudEventOverlap is
// re-read on every later pass so an event that CloudTrail delivered late (the API can lag ~15
// minutes) is not skipped past. Same shape as identitylog's cursor.
const (
	CloudEventWindow  = 24 * time.Hour
	CloudEventOverlap = time.Hour
)

// CloudEventResult is what one CloudTrail poll did, for the manual door and the pass log.
type CloudEventResult struct {
	Connections []string          `json:"connections"`       // connection ids actually read
	Failed      map[string]string `json:"failed,omitempty"`  // connection id → why
	Records     int               `json:"records"`           // CloudTrail records read
	Dropped     int               `json:"dropped,omitempty"` // records that could not be normalised
	Events      int               `json:"events"`            // detector events after normalisation
	Threats     []cloudcdr.Threat `json:"threats"`           // what the rules matched
	Findings    []types.Finding   `json:"findings"`          // stored this pass
	Unread      map[string]string `json:"unread,omitempty"`  // connection id → the span a truncated read did NOT cover
}

// SyncCloudEvents polls each connected AWS account's CloudTrail event history since its cursor, runs
// the CDR rules over the records, and stores the findings. This is what makes internal/cloudcdr a
// LIVE capability: its rules existed with no source but a customer-built forwarder, so a root
// console login or a trail being stopped was detected only when somebody else's pipeline posted it.
//
// Grounded (§10): no reader wired, no active AWS connection, or a read that fails → that account was
// NOT observed this pass (named in Failed), never an empty window that reads as "no threat". The
// cursor advances only past events actually read; a truncated read names the span it left unread.
// `ran` is true only when at least one account was read.
func (s *Service) SyncCloudEvents(ctx context.Context, tenantID string) (CloudEventResult, bool) {
	res := CloudEventResult{Findings: []types.Finding{}, Threats: []cloudcdr.Threat{}, Failed: map[string]string{}, Unread: map[string]string{}}
	if s.Store == nil || s.NewID == nil || s.CloudEventReader == nil {
		return res, false
	}
	t, err := s.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return res, false
	}
	conns, err := s.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return res, false
	}
	now := s.now()
	var events []cloudcdr.Event
	latest := map[string]time.Time{}
	for _, c := range conns {
		if c.Kind != platform.ConnAWS || c.Status != platform.ConnActive {
			continue
		}
		reader := s.CloudEventReader(c)
		if reader == nil {
			res.Failed[c.ID] = "no CloudTrail reader for this connection"
			continue
		}
		since := now.Add(-CloudEventWindow)
		if cur := t.CloudEventCursors[c.ID]; !cur.IsZero() && cur.Add(-CloudEventOverlap).After(since) {
			since = cur.Add(-CloudEventOverlap)
		}
		page, ferr := reader.LookupEvents(ctx, since, now)
		if ferr != nil {
			res.Failed[c.ID] = ferr.Error()
			slog.Warn("[scan] cloudtrail not read", "tenant", tenantID, "connection", c.ID, "err", ferr.Error())
			continue
		}
		res.Connections = append(res.Connections, c.ID)
		evs, dropped := cloudcdr.FromCloudTrailBatch(page.Records)
		res.Records += len(page.Records)
		res.Dropped += dropped
		events = append(events, evs...)
		if !page.Latest.IsZero() {
			latest[c.ID] = page.Latest
		}
		if page.Truncated {
			res.Unread[c.ID] = fmt.Sprintf("read stopped at %d records; events between %s and %s were not examined",
				len(page.Records), since.Format(time.RFC3339), page.Oldest.Format(time.RFC3339))
		}
	}
	if len(res.Connections) == 0 {
		return res, false
	}
	res.Events = len(events)
	res.Threats = cloudcdr.Detect(events)
	findings := l15.Enrich(cloudcdr.Findings(res.Threats)) // §11 parity with POST /v1/cloud/events
	for i := range findings {
		findings[i].ID = s.NewID()
		if err := s.Store.PutFinding(ctx, tenantID, findings[i]); err != nil {
			slog.Warn("[scan] cloud CDR finding could not be stored", "tenant", tenantID, "rule", findings[i].RuleID, "err", err.Error())
			continue
		}
		res.Findings = append(res.Findings, findings[i])
	}
	s.foldPosture(ctx, tenantID, res.Findings)
	if t.CloudEventCursors == nil {
		t.CloudEventCursors = map[string]time.Time{}
	}
	for k, v := range latest {
		if v.After(t.CloudEventCursors[k]) {
			t.CloudEventCursors[k] = v
		}
	}
	if t.PostureAssessed == nil {
		t.PostureAssessed = map[string]time.Time{}
	}
	t.PostureAssessed["cloudcdr"] = now
	if err := s.Store.PutTenant(ctx, t); err != nil {
		slog.Warn("[scan] cloudtrail cursor not saved", "tenant", tenantID, "err", err.Error())
	}
	slog.Info("[scan] cloudtrail assessed", "tenant", tenantID, "connections", res.Connections, "records", res.Records,
		"events", res.Events, "findings", len(res.Findings), "failed", len(res.Failed), "unread", len(res.Unread))
	return res, true
}

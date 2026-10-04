package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// boardmail.go: the board report, delivered on a schedule.
//
// The report existed as a page and a download, which means it reached a board only when someone
// remembered to open it the night before the meeting. A security programme a CTO reports on monthly
// should arrive monthly. Three rules shape the delivery, each because the alternative would quietly make
// the email worse than the page:
//
//   - ONE ASSEMBLY. The email is built by buildBoardReport, the same function behind the page, so an
//     emailed report cannot carry a number the page does not.
//   - SEAT HOLDERS ONLY, re-checked at send time. The report names exposure that is exploitable today; it
//     goes only to people the workspace already lets read it. An auditor seat is the read-only way to give
//     a board member access. A recipient whose seat is removed stops receiving it on the next send, rather
//     than continuing to receive a list of open holes because they were once on a distribution list.
//   - A DELIVERY PROBLEM IS VISIBLE. The schedule advances only when a copy was delivered; the last
//     attempt and its error are stored and shown in Settings, so "the board stopped getting it" is a
//     sentence on a page rather than something discovered at the meeting.

const maxBoardRecipients = 20

// boardDigestView is what Settings reads.
type boardDigestView struct {
	Enabled            bool      `json:"enabled"`
	Cadence            string    `json:"cadence,omitempty"`
	Recipients         []string  `json:"recipients"`
	ConfiguredBy       string    `json:"configured_by,omitempty"`
	LastSentAt         time.Time `json:"last_sent_at,omitzero"`
	LastAttemptAt      time.Time `json:"last_attempt_at,omitzero"`
	LastError          string    `json:"last_error,omitempty"`
	NextDue            time.Time `json:"next_due,omitzero"`
	DeliveryConfigured bool      `json:"delivery_configured"`
	// DeliveryNote is set when nothing will actually be sent, and says why — a saved schedule on a
	// deployment with no mail relay would otherwise read as a working one.
	DeliveryNote string `json:"delivery_note,omitempty"`
}

func (d Deps) mailOK() bool { return d.Mailer != nil && d.Mailer.Configured() }

func (d Deps) boardDigestView(t platform.Tenant) boardDigestView {
	v := boardDigestView{Recipients: []string{}, DeliveryConfigured: d.mailOK()}
	if bd := t.BoardDigest; bd != nil {
		v.Enabled, v.Cadence, v.Recipients, v.ConfiguredBy = true, bd.Cadence, bd.Recipients, bd.ConfiguredBy
		v.LastSentAt, v.LastAttemptAt, v.LastError = bd.LastSentAt, bd.LastAttemptAt, bd.LastError
		if nd := bd.NextDue(); !nd.IsZero() {
			v.NextDue = nd
		}
	}
	if !v.DeliveryConfigured {
		v.DeliveryNote = "Email delivery is not configured on this deployment (no SMTP relay), so a saved schedule " +
			"sends nothing. The report is still available to download."
	}
	return v
}

func (d Deps) handleGetBoardDigest(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	writeJSON(w, http.StatusOK, d.boardDigestView(t))
}

// seatEmails maps each seat holder's lower-cased address to itself.
func (d Deps) seatEmails(ctx context.Context, tenantID string) (map[string]bool, error) {
	users, err := d.Store.ListUsers(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, u := range users {
		if e := strings.ToLower(strings.TrimSpace(u.Email)); e != "" {
			out[e] = true
		}
	}
	return out, nil
}

func (d Deps) handlePutBoardDigest(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Enabled    bool     `json:"enabled"`
		Cadence    string   `json:"cadence"`
		Recipients []string `json:"recipients"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	ctx := r.Context()
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	if !body.Enabled {
		t.BoardDigest = nil
		if err := d.Store.PutTenant(ctx, t); err != nil {
			respond(w, nil, err)
			return
		}
		d.recordBoardDigest(tenantID, "board digest turned off", nil)
		writeJSON(w, http.StatusOK, d.boardDigestView(t))
		return
	}
	cadence := strings.ToLower(strings.TrimSpace(body.Cadence))
	if !platform.BoardDigestCadences[cadence] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cadence must be weekly or monthly", "code": "bad_cadence"})
		return
	}
	seats, err := d.seatEmails(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	var recips, notSeats []string
	seen := map[string]bool{}
	for _, e := range body.Recipients {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		if !seats[e] {
			notSeats = append(notSeats, e)
			continue
		}
		recips = append(recips, e)
	}
	// Refused, not filtered: dropping an address silently would leave the owner believing a board member
	// is on the list. The fix is a seat (an auditor seat is read-only), which is also what gives that person
	// access to the page the email summarises.
	if len(notSeats) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "the board report lists exposure that is exploitable today, so it is only sent to people who " +
				"already have a seat in this workspace. Invite them first — an auditor seat gives read-only access. " +
				"Not a seat: " + strings.Join(notSeats, ", "),
			"code":      "recipient_not_a_seat",
			"not_seats": notSeats,
		})
		return
	}
	if len(recips) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name at least one recipient", "code": "no_recipients"})
		return
	}
	if len(recips) > maxBoardRecipients {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("at most %d recipients", maxBoardRecipients), "code": "too_many_recipients"})
		return
	}
	sort.Strings(recips)
	by := "platform"
	if u, ok := d.actingUser(r); ok {
		by = u.Email
	}
	prev := t.BoardDigest
	bd := &platform.BoardDigest{Cadence: cadence, Recipients: recips, ConfiguredBy: by, ConfiguredAt: time.Now().UTC()}
	// Changing who receives it or how often does not reset the clock: a schedule edited the day after a
	// send does not send again tomorrow.
	if prev != nil {
		bd.LastSentAt, bd.LastAttemptAt, bd.LastError = prev.LastSentAt, prev.LastAttemptAt, prev.LastError
	}
	t.BoardDigest = bd
	if err := d.Store.PutTenant(ctx, t); err != nil {
		respond(w, nil, err)
		return
	}
	d.recordBoardDigest(tenantID, "board digest scheduled", map[string]any{"cadence": cadence, "recipients": recips, "by": by})
	writeJSON(w, http.StatusOK, d.boardDigestView(t))
}

// handleSendBoardDigestNow sends the report to the scheduled recipients immediately — the way an owner
// checks delivery works without waiting a month — and counts as that period's send.
func (d Deps) handleSendBoardDigestNow(w http.ResponseWriter, r *http.Request, tenantID string) {
	if !d.mailOK() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "email delivery is not configured on this deployment", "code": "no_mailer"})
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	if t.BoardDigest == nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no board digest is scheduled", "code": "not_scheduled"})
		return
	}
	t2, err := d.sendBoardDigest(r.Context(), tenantID, time.Now().UTC())
	if err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, d.boardDigestView(t2))
}

// SendDueBoardDigest is called on every monitoring pass. It sends only when a schedule exists, delivery is
// configured, and the cadence has elapsed since the last DELIVERED copy.
func (d Deps) SendDueBoardDigest(ctx context.Context, tenantID string) {
	if !d.mailOK() {
		return
	}
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil || t.BoardDigest == nil {
		return
	}
	now := time.Now().UTC()
	if nd := t.BoardDigest.NextDue(); !nd.IsZero() && now.Before(nd) {
		return
	}
	if _, err := d.sendBoardDigest(ctx, tenantID, now); err != nil {
		slog.Warn("board digest failed", "tenant", tenantID, "err", err)
	}
}

// sendBoardDigest builds the report once, sends it to every recipient who STILL holds a seat, and records
// the outcome. Returns the tenant as stored afterwards.
func (d Deps) sendBoardDigest(ctx context.Context, tenantID string, now time.Time) (platform.Tenant, error) {
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return t, err
	}
	bd := t.BoardDigest
	if bd == nil {
		return t, nil
	}
	rep, err := d.buildBoardReport(ctx, tenantID, now)
	if err != nil {
		return t, err
	}
	seats, err := d.seatEmails(ctx, tenantID)
	if err != nil {
		return t, err
	}
	subject := "Security report — " + now.Format("2 January 2006")
	body := renderBoardEmail(rep, strings.TrimRight(d.AppURL, "/")+"/board")
	var sent int
	var problems []string
	for _, e := range bd.Recipients {
		if !seats[strings.ToLower(e)] {
			problems = append(problems, e+": no longer holds a seat, so it was not sent")
			continue
		}
		if err := d.Mailer.Send(ctx, e, subject, body); err != nil {
			problems = append(problems, e+": "+err.Error())
			continue
		}
		sent++
	}
	// Re-read before writing so a Settings change made while the report was being built is not lost; only
	// the delivery fields are touched, and only if the schedule still exists.
	cur, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return t, err
	}
	if cur.BoardDigest == nil {
		return cur, nil
	}
	cur.BoardDigest.LastAttemptAt = now
	cur.BoardDigest.LastError = strings.Join(problems, "; ")
	if sent > 0 {
		cur.BoardDigest.LastSentAt = now
	}
	if err := d.Store.PutTenant(ctx, cur); err != nil {
		return cur, err
	}
	d.recordBoardDigest(tenantID, "board digest sent", map[string]any{"delivered": sent, "problems": problems})
	return cur, nil
}

func (d Deps) recordBoardDigest(tenantID, what string, extra map[string]any) {
	if d.Recorder == nil {
		return
	}
	m := map[string]any{"tenant_id": tenantID}
	for k, v := range extra {
		m[k] = v
	}
	d.Recorder.Record(what, "board_digest", m, what)
}

// renderBoardEmail renders the report as HTML. Every figure comes from the report as assembled; the
// headline — which carries the "never scanned" and "unmeasured, not safe" caveats — leads, and the
// caveats close it, because a reader of an email reads the top and maybe the bottom.
func renderBoardEmail(r boardReport, link string) string {
	esc := html.EscapeString
	var b strings.Builder
	fmt.Fprintf(&b, "<h2>Security report</h2><p><em>%s</em></p><p><strong>%s</strong></p>",
		esc(r.GeneratedAt.Format("2 January 2006")), esc(r.Headline))
	fmt.Fprintf(&b, "<h3>Open issues</h3><ul><li>Open: %d (critical %d, high %d, medium %d, low %d)</li>"+
		"<li>Proven exploitable on your systems: %d</li><li>On CISA's actively-exploited list: %d (ransomware-linked: %d)</li></ul>",
		r.Proven.OpenIssues, r.Proven.BySeverity["critical"], r.Proven.BySeverity["high"], r.Proven.BySeverity["medium"],
		r.Proven.BySeverity["low"], r.Proven.Exploited, r.Proven.KEV, r.Proven.Ransomware)
	fmt.Fprintf(&b, "<h3>Is exposure going down?</h3><ul><li>Last 30 days: %d opened, %d stopped appearing, %d proven closed by re-test (all time)</li>"+
		"<li>Objective: %s</li></ul>", r.Exposure.Opened30, r.Exposure.Closed30, r.Exposure.ConfirmedFixed, esc(r.Exposure.Objective.Reason))
	b.WriteString("<h3>Top fixes</h3>")
	if len(r.TopFixes) == 0 {
		b.WriteString("<p>Nothing open to fix.</p>")
	} else {
		b.WriteString("<ol>")
		for _, s := range r.TopFixes {
			fmt.Fprintf(&b, "<li><strong>%s</strong> — closes %d finding(s) across %d asset(s)</li>", esc(s.Title), s.Closes, len(s.Assets))
		}
		b.WriteString("</ol>")
	}
	fmt.Fprintf(&b, "<h3>Risk decisions</h3><ul><li>In force: %d (with no review date: %d)</li><li>Lapsed and back on the list: %d</li></ul>",
		r.Decisions.InForce, r.Decisions.Undated, r.Decisions.Lapsed)
	fmt.Fprintf(&b, "<h3>Coverage</h3><p>%d of %d asset(s) scanned.</p>", r.Coverage.ScannedAssets, r.Coverage.TotalAssets)
	b.WriteString("<h3>What these numbers do not say</h3><ul>")
	for _, c := range r.Caveats {
		fmt.Fprintf(&b, "<li>%s</li>", esc(c))
	}
	b.WriteString("</ul>")
	if link != "/board" {
		fmt.Fprintf(&b, `<p><a href="%s">Open the full report</a></p>`, esc(link))
	}
	b.WriteString("<p><small>You receive this because you hold a seat in this workspace and are on its board-report schedule. " +
		"The workspace owner can change the schedule in Settings.</small></p>")
	return b.String()
}

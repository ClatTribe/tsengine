package platformapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// invite_roster.go turns the HRIS roster into EMPLOYEE seats in one act.
//
// The training programme was unusable at any real size without this: the employee seat exists so a
// colleague can be asked to do their training without being handed the security estate, but the only
// way to create one was POST /v1/auth/invite, one person at a time, each with a temp password to
// relay by hand. Forty people is forty forms. Meanwhile the HRIS join already knows exactly who works
// here — that is what it is FOR — so the seat list can come from the record that defines it.
//
// THE RULES, each a refusal rather than a convenience:
//
//   - Only ACTIVE employment gets a seat. Someone who has left does not owe training (the roster rule
//     in training.RosterFrom) and a seat for them is an account nobody will close; someone not yet
//     started is invited on their start date by the next run, not today with a credential that sits in
//     a mailbox they do not have yet. Both are NAMED in the response as skipped, with the reason.
//   - Only the EMPLOYEE role is ever created here. A bulk act must not be able to mint member seats —
//     the role that reads every finding and approves fixes — and there is no parameter to ask for one.
//   - An address that already holds ANY seat is left exactly as it is: never re-invited (the credential
//     would reset), never downgraded (an owner in the HRIS export is still the owner). Reported as
//     already seated, with the role, so the owner can see the join worked.
//   - No work email means no seat, and the person is NAMED (by HRIS name and id) rather than dropped,
//     because the owner reading "38 invited" from a roster of 40 needs to know which two and why.
//   - No roster at all is refused, not rendered as "nobody to invite": an empty HRIS sync and a company
//     with no employees look the same from here, and the fix is to connect the HRIS, which the
//     response says.
//   - Idempotent by construction. A second run invites only whoever joined since, because everyone
//     from the first run is now already seated.
//
// The credential path is the single invite's, unchanged: mailed and NOT returned when SMTP is
// configured; returned for manual relay when it is not, or when delivery failed for that address.
// A run is bounded (rosterInviteMax) so one request cannot mint a thousand accounts and mail them; the
// remainder is reported and the next run picks it up.

const rosterInviteMax = 200

type rosterSeat struct {
	Email      string `json:"email"`
	Name       string `json:"name,omitempty"`
	Department string `json:"department,omitempty"`
	// Role is the seat the address ALREADY holds (already_seated only).
	Role string `json:"role,omitempty"`
	// Reason says why this person was skipped (skipped only).
	Reason string `json:"reason,omitempty"`
	// HRISID identifies a skipped person who has no work email to be named by.
	HRISID string `json:"hris_id,omitempty"`
}

type rosterInvitePlan struct {
	// Roster is the size of the HRIS roster the plan was computed over, every status included.
	Roster int `json:"roster"`
	// NoRoster is true when the HRIS has synced nobody — connect one; nothing here can be invited.
	NoRoster bool `json:"no_roster"`
	// Mailer says whether invites will be emailed (true) or returned as temp passwords (false), so
	// the owner knows BEFORE pressing the button whether they are about to receive forty credentials
	// to relay by hand.
	Mailer bool `json:"mailer"`
	// ToInvite is who a run would seat — bounded to rosterInviteMax; Remaining is the overflow.
	ToInvite      []rosterSeat `json:"to_invite"`
	Remaining     int          `json:"remaining"`
	AlreadySeated []rosterSeat `json:"already_seated"`
	Skipped       []rosterSeat `json:"skipped"`
	Detail        string       `json:"detail"`
}

// planRosterInvites computes, without side effects, who a run would invite and who it would not.
func (d Deps) planRosterInvites(ctx context.Context, tenantID string) (rosterInvitePlan, error) {
	emps, err := d.Store.ListEmployees(ctx, tenantID)
	if err != nil {
		return rosterInvitePlan{}, err
	}
	users, err := d.Store.ListUsers(ctx, tenantID)
	if err != nil {
		return rosterInvitePlan{}, err
	}
	seated := map[string]platform.User{}
	for _, u := range users {
		seated[strings.ToLower(strings.TrimSpace(u.Email))] = u
	}

	p := rosterInvitePlan{Roster: len(emps), Mailer: d.mailerConfigured(),
		ToInvite: []rosterSeat{}, AlreadySeated: []rosterSeat{}, Skipped: []rosterSeat{}}
	if len(emps) == 0 {
		p.NoRoster = true
		p.Detail = "The HRIS roster is empty, so there is nobody to invite. Connect Merge or Finch under Settings → People & devices and sync; every active employee then appears here."
		return p, nil
	}

	seen := map[string]bool{}
	for _, e := range emps {
		email := strings.ToLower(strings.TrimSpace(e.WorkEmail))
		switch {
		case e.Status != platform.EmploymentActive:
			// Named, not dropped. A leaver is not invited because they do not owe training and the
			// seat would outlive them; a pending hire is not invited because the credential would sit
			// in a mailbox they do not have yet — the next run after their start date seats them.
			reason := "not an active employee"
			if e.Status != "" {
				reason += " (" + e.Status + ")"
			}
			if e.Status == platform.EmploymentPending && e.StartDate != "" {
				reason += " — starts " + e.StartDate
			}
			p.Skipped = append(p.Skipped, rosterSeat{Email: email, Name: e.Name, HRISID: e.ID, Reason: reason})
		case !strings.Contains(email, "@"):
			p.Skipped = append(p.Skipped, rosterSeat{Name: e.Name, HRISID: e.ID, Department: e.Department,
				Reason: "no work email in the HRIS record — add one there and sync, or invite them by hand"})
		case seen[email]:
			// Two HRIS records with one address describe one person; one seat.
		default:
			seen[email] = true
			if u, ok := seated[email]; ok {
				p.AlreadySeated = append(p.AlreadySeated, rosterSeat{Email: email, Name: firstNonEmpty(u.Name, e.Name), Role: u.Role})
				continue
			}
			p.ToInvite = append(p.ToInvite, rosterSeat{Email: email, Name: e.Name, Department: e.Department})
		}
	}
	for _, s := range [][]rosterSeat{p.ToInvite, p.AlreadySeated, p.Skipped} {
		sort.Slice(s, func(i, j int) bool { return s[i].Email+s[i].HRISID < s[j].Email+s[j].HRISID })
	}
	if len(p.ToInvite) > rosterInviteMax {
		p.Remaining = len(p.ToInvite) - rosterInviteMax
		p.ToInvite = p.ToInvite[:rosterInviteMax]
	}
	p.Detail = rosterPlanDetail(p)
	return p, nil
}

func rosterPlanDetail(p rosterInvitePlan) string {
	var b strings.Builder
	b.WriteString(plural(len(p.ToInvite), "person", "people"))
	b.WriteString(" on the HRIS roster would get an employee seat")
	if len(p.AlreadySeated) > 0 {
		b.WriteString("; " + plural(len(p.AlreadySeated), "already has", "already have") + " one and will not be touched")
	}
	if len(p.Skipped) > 0 {
		b.WriteString("; " + plural(len(p.Skipped), "is", "are") + " skipped and named below")
	}
	if p.Remaining > 0 {
		b.WriteString("; " + plural(p.Remaining, "more waits", "more wait") + " for the next run (each run seats at most " + itoa(rosterInviteMax) + ")")
	}
	b.WriteString(".")
	if len(p.ToInvite) > 0 {
		if p.Mailer {
			b.WriteString(" Each will be emailed a one-time password they must change at first sign-in.")
		} else {
			b.WriteString(" No SMTP is configured, so their one-time passwords will be shown to you once to relay securely.")
		}
	}
	return b.String()
}

// handleRosterInvitePreview answers "who would this invite" without inviting anyone.
func (d Deps) handleRosterInvitePreview(w http.ResponseWriter, r *http.Request, s platform.Session) {
	if !d.requireOwner(w, r, s) {
		return
	}
	p, err := d.planRosterInvites(r.Context(), s.TenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, p)
}

type rosterInvited struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
	// Emailed says the credential went to the invitee and was NOT returned here.
	Emailed bool `json:"emailed"`
	// TempPassword is present only when it could not be emailed — for the owner to relay once.
	TempPassword string `json:"temp_password,omitempty"`
}

type rosterInviteResult struct {
	rosterInvitePlan
	Invited []rosterInvited `json:"invited"`
	Failed  []rosterSeat    `json:"failed"`
	Note    string          `json:"note"`
}

// handleRosterInvite seats every active HRIS employee who does not already hold one.
func (d Deps) handleRosterInvite(w http.ResponseWriter, r *http.Request, s platform.Session) {
	if !d.requireOwner(w, r, s) {
		return
	}
	p, err := d.planRosterInvites(r.Context(), s.TenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if p.NoRoster {
		// Refused rather than "0 invited": an empty roster and a company with everyone already
		// seated must not produce the same success.
		writeJSON(w, http.StatusConflict, map[string]any{"error": p.Detail, "code": "no_roster"})
		return
	}
	res := rosterInviteResult{rosterInvitePlan: p, Invited: []rosterInvited{}, Failed: []rosterSeat{}}
	// The plan is reported as what was ATTEMPTED; ToInvite becomes the invited/failed lists.
	res.ToInvite = []rosterSeat{}
	for _, seat := range p.ToInvite {
		u, temp, err := d.provisionSeat(r.Context(), s.TenantID, seat.Email, seat.Name, platform.RoleEmployee)
		if err != nil {
			if errors.Is(err, errSeatExists) {
				// Raced with a hand invite between preview and run; the join still holds.
				res.AlreadySeated = append(res.AlreadySeated, rosterSeat{Email: seat.Email, Name: seat.Name, Role: "?"})
				continue
			}
			res.Failed = append(res.Failed, rosterSeat{Email: seat.Email, Name: seat.Name, Reason: err.Error()})
			continue
		}
		inv := rosterInvited{Email: u.Email, Name: u.Name}
		if d.deliverInvite(r.Context(), u.Email, temp) {
			inv.Emailed = true
		} else {
			inv.TempPassword = temp
		}
		res.Invited = append(res.Invited, inv)
	}
	if d.Recorder != nil {
		d.Recorder.Record("employee seats invited from the HRIS roster", "team",
			map[string]any{"tenant_id": s.TenantID, "by": s.UserID, "invited": len(res.Invited),
				"already_seated": len(res.AlreadySeated), "skipped": len(res.Skipped), "failed": len(res.Failed),
				"remaining": res.Remaining, "emailed": p.Mailer},
			"SOC 2 CC1.4/CC2.2 security-awareness programme — the employee seats it runs on")
	}
	res.Note = rosterResultNote(res)
	writeJSON(w, http.StatusOK, res)
}

func rosterResultNote(res rosterInviteResult) string {
	var b strings.Builder
	b.WriteString("Invited " + plural(len(res.Invited), "person", "people") + " as employees")
	if len(res.Failed) > 0 {
		b.WriteString("; " + plural(len(res.Failed), "invite", "invites") + " failed and " + pluralIs(len(res.Failed)) + " named below")
	}
	if len(res.AlreadySeated) > 0 {
		b.WriteString("; " + plural(len(res.AlreadySeated), "already had", "already had") + " a seat")
	}
	if len(res.Skipped) > 0 {
		b.WriteString("; " + plural(len(res.Skipped), "was", "were") + " skipped")
	}
	if res.Remaining > 0 {
		b.WriteString("; run again to seat the remaining " + itoa(res.Remaining))
	}
	b.WriteString(".")
	unmailed := 0
	for _, i := range res.Invited {
		if !i.Emailed {
			unmailed++
		}
	}
	if unmailed > 0 {
		b.WriteString(" " + plural(unmailed, "one-time password is", "one-time passwords are") +
			" shown once below — relay each securely; every one must be changed at first sign-in.")
	}
	return b.String()
}

// requireOwner refuses every seat but the workspace owner's. Bulk seating is an owner's act for the
// same reason a single invite is, and more so: it creates accounts for people who did not ask.
func (d Deps) requireOwner(w http.ResponseWriter, r *http.Request, s platform.Session) bool {
	actor, err := d.Store.GetUser(r.Context(), s.UserID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
		return false
	}
	if actor.Role != platform.RoleOwner {
		writeJSON(w, http.StatusForbidden, errBody("only the workspace owner can invite teammates"))
		return false
	}
	return true
}

var errSeatExists = errors.New("a user with that email already exists")

// provisionSeat creates the account behind an invite: a one-time password (hashed) the person must
// change at first sign-in. ONE implementation for the single invite and the roster invite, so the
// two cannot drift on what a freshly invited account looks like.
func (d Deps) provisionSeat(ctx context.Context, tenantID, email, name, role string) (platform.User, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if _, err := d.Store.GetUserByEmail(ctx, email); err == nil {
		return platform.User{}, "", errSeatExists
	} else if !errors.Is(err, store.ErrNotFound) {
		return platform.User{}, "", err
	}
	tok, err := authn.NewToken()
	if err != nil {
		return platform.User{}, "", err
	}
	temp := tok[:14] // a usable one-time password (≥8 chars)
	hash, err := authn.HashPassword(temp)
	if err != nil {
		return platform.User{}, "", err
	}
	u := platform.User{
		ID: d.newID("usr"), TenantID: tenantID, Email: email, Name: strings.TrimSpace(name),
		Role: role, PasswordHash: hash, CreatedAt: time.Now().UTC(),
		MustChangePassword: true, // the temp password is the owner's; force the person to set their own
	}
	if err := d.Store.PutUser(ctx, u); err != nil {
		return platform.User{}, "", err
	}
	u.PasswordHash = ""
	return u, temp, nil
}

// deliverInvite mails the credential when SMTP is configured and reports whether it went. A false
// return means the caller must hand the temp password back for manual relay — the account exists
// either way, and failing the request would strand it.
func (d Deps) deliverInvite(ctx context.Context, email, temp string) bool {
	if !d.mailerConfigured() {
		return false
	}
	if err := d.mailer().Send(ctx, email, "You've been invited to TensorShield", inviteEmailHTML(d.PublicURL, email, temp)); err != nil {
		slog.Warn("[auth] invite email failed — returning the temp password for manual relay", "email", email, "err", err)
		return false
	}
	return true
}

// plural, itoa and firstNonEmpty are the package's existing helpers (systemstate.go, custom_frameworks.go, slack.go).

func pluralIs(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/training"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// training.go is the door to the security-awareness programme (SOC 2 CC1.4/CC2.2, ISO A.6.3,
// PCI 12.6, HIPAA 164.308(a)(5)).
//
// TWO WRITE PATHS, DELIBERATELY NOT ONE. They record different claims and the difference is the
// whole point of the package:
//
//   - POST /v1/training/complete — the SIGNED-IN person confirms they have read a module we
//     rendered. The subject is taken from the session and can never be supplied by the caller,
//     because "delivered" asserts that WE showed it to THAT person and the session is the only
//     evidence of that. A platform-token call has no person behind it and is refused rather than
//     attributed to somebody.
//   - POST /v1/training/record — somebody records that a colleague was trained ELSEWHERE. The tier
//     is forced to attested and the recorder is taken from the session, so this endpoint cannot be
//     used to mint the stronger claim on someone else's behalf.
//
// The roster is assembled from the HRIS (when one is connected) and this product's own users, and
// each person carries the source they came from — an HRIS roster and a list of people who happen to
// have logged in here are very different statements about who works at a company, and a completion
// rate is only as honest as the denominator under it.

const (
	rosterSourceHRIS = "hris"
	rosterSourceApp  = "workspace_users"
)

type trainingResponse struct {
	Curriculum training.Curriculum `json:"curriculum"`
	Summary    training.Summary    `json:"summary"`
	Statuses   []training.Status   `json:"statuses"`
	// Me is the signed-in person's address, so the page can lead with what THEY owe rather than
	// making them find their own row. Empty on the platform-token path, where there is no person.
	Me string `json:"me,omitempty"`
}

// handleTraining returns the curriculum, every person's status, and the honest summary.
func (d Deps) handleTraining(w http.ResponseWriter, r *http.Request, tenantID string) {
	cur := training.Default()
	people, err := d.trainingRoster(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	comps, err := d.Store.ListTrainingCompletions(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	sts := training.Evaluate(cur, people, comps, time.Now())
	writeJSON(w, http.StatusOK, trainingResponse{
		Curriculum: cur,
		Summary:    training.Summarize(cur, people, sts, comps),
		Statuses:   sts,
		Me:         d.actingEmail(r),
	})
}

// handleTrainingComplete records that the signed-in person read a module HERE.
func (d Deps) handleTrainingComplete(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		ModuleID string `json:"module_id"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	subject := d.actingEmail(r)
	if subject == "" {
		// No session means no person. Attributing a delivered completion to the tenant, the owner, or
		// anyone else would put a name against training nobody watched them read.
		writeJSON(w, http.StatusForbidden, errBody(
			"only a signed-in person can confirm they read a module — this records that YOU read it"))
		return
	}
	c, err := training.NewCompletion(subject, body.ModuleID, training.TierDelivered, "", "", body.Note, time.Now(), training.Default())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	d.storeCompletion(w, r, tenantID, c, "security training completed")
}

// handleTrainingRecord records that someone was trained ELSEWHERE — a second-hand claim, and stored
// as one.
func (d Deps) handleTrainingRecord(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Subject  string `json:"subject"`
		ModuleID string `json:"module_id"`
		Provider string `json:"provider"`
		Note     string `json:"note"`
		// When the training actually happened, YYYY-MM-DD. Optional; absent means today. It matters
		// because currency is measured from the completion date, and recording a two-year-old course
		// as if it happened today would reset a clock that has already run out.
		On string `json:"on"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	recorder := d.actingEmail(r)
	if recorder == "" {
		writeJSON(w, http.StatusForbidden, errBody(
			"only a signed-in person can record training somebody else completed — the record names who entered it"))
		return
	}
	at := time.Now()
	if on := strings.TrimSpace(body.On); on != "" {
		parsed, perr := time.Parse("2006-01-02", on)
		if perr != nil {
			writeJSON(w, http.StatusBadRequest, errBody(`"on" must be a date like 2026-04-01`))
			return
		}
		if parsed.After(time.Now().AddDate(0, 0, 1)) {
			// A completion in the future is not a record of anything, and it would sit "current" for a
			// year on the strength of a typo.
			writeJSON(w, http.StatusBadRequest, errBody("that date is in the future — record training after it happens"))
			return
		}
		at = parsed
	}
	c, err := training.NewCompletion(body.Subject, body.ModuleID, training.TierAttested, body.Provider, recorder, body.Note, at, training.Default())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	d.storeCompletion(w, r, tenantID, c, "security training recorded from an external provider")
}

// storeCompletion persists one completion and returns the refreshed programme, so the caller renders
// the same state the next reader would see rather than its own optimistic guess.
func (d Deps) storeCompletion(w http.ResponseWriter, r *http.Request, tenantID string, c platform.TrainingCompletion, what string) {
	c.TenantID = tenantID
	if err := d.Store.PutTrainingCompletion(r.Context(), c); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record(what, "security_training",
			map[string]any{"tenant_id": tenantID, "subject": c.Subject, "module": c.ModuleID,
				"tier": string(c.Tier), "provider": c.Provider, "recorded_by": c.RecordedBy,
				"curriculum_version": c.CurriculumVersion},
			"SOC 2 CC1.4/CC2.2 · ISO 27001 A.6.3 · PCI 12.6 · HIPAA 164.308(a)(5) security-awareness training")
	}
	d.handleTraining(w, r, tenantID)
}

// actingEmail is the signed-in person's address, or "" when the request came in on the platform
// token — which is a machine, not a person.
func (d Deps) actingEmail(r *http.Request) string {
	s, ok := d.resolveSession(r)
	if !ok {
		return ""
	}
	u, err := d.Store.GetUser(r.Context(), s.UserID)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Email))
}

// trainingRoster is everyone expected to complete the curriculum: the HRIS roster where one is
// connected, plus this product's own users.
//
// Only ACTIVE employees are assigned. Someone who has left does not owe training, and listing them
// would fill the outstanding column with people nobody can chase — the same reason the HRIS join
// treats a future end date as still employed rather than as a leaver.
//
// The HRIS wins on a duplicate: both sources describe the same human, and the HRIS knows their name
// and their employment status while the user table knows only that they logged in.
func (d Deps) trainingRoster(ctx context.Context, tenantID string) ([]training.Person, error) {
	byEmail := map[string]training.Person{}

	emps, err := d.Store.ListEmployees(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, e := range emps {
		if e.Status != platform.EmploymentActive {
			continue
		}
		email := strings.ToLower(strings.TrimSpace(e.WorkEmail))
		if email == "" {
			continue
		}
		byEmail[email] = training.Person{Email: email, Name: e.Name, Source: rosterSourceHRIS}
	}

	users, err := d.Store.ListUsers(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		email := strings.ToLower(strings.TrimSpace(u.Email))
		if email == "" {
			continue
		}
		if _, ok := byEmail[email]; ok {
			continue // the HRIS record is the better one
		}
		byEmail[email] = training.Person{Email: email, Name: u.Name, Source: rosterSourceApp}
	}

	out := make([]training.Person, 0, len(byEmail))
	for _, p := range byEmail {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

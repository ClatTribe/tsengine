// Package identitythreat is the real-time identity-threat (ITDR) detector (ADR 0010 Phase 5) —
// the gap vs Nudge/Push. internal/operate gives point-in-time identity POSTURE (MFA gaps, stale
// accounts, risky grants); what was missing is detecting suspicious identity EVENTS from the
// IdP audit stream (Okta System Log / Google Admin / M365 audit): impossible travel, a new admin
// grant, MFA removal, password spray. Deterministic rules over the event stream, LLM-free,
// grounded (§10 — every threat cites the events that triggered it). The live event ingestion is
// the gated connector half; this is the offline-testable detection core.
package identitythreat

import (
	"fmt"
	"sort"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// EventType classifies an identity audit event.
type EventType string

const (
	EventLogin      EventType = "login"              // a successful authentication
	EventLoginFail  EventType = "login_failed"       // a failed authentication
	EventRoleGrant  EventType = "role_grant"         // a role/privilege was granted
	EventMFARemoved EventType = "mfa_factor_removed" // an MFA factor was removed (security downgrade)
)

// Event is one normalized identity audit event.
type Event struct {
	ID      string    `json:"id"`
	User    string    `json:"user"`
	Type    EventType `json:"type"`
	Time    time.Time `json:"time"`
	IP      string    `json:"ip,omitempty"`
	Country string    `json:"country,omitempty"` // geo from the IdP event (impossible-travel signal)
	Detail  string    `json:"detail,omitempty"`  // e.g. the role name for role_grant
	Admin   bool      `json:"admin,omitempty"`   // role_grant: is it a privileged/admin role
}

// Threat is a detected identity-threat finding (grounded: Evidence cites the source events).
type Threat struct {
	Rule     string         `json:"rule"`
	User     string         `json:"user"`
	Severity types.Severity `json:"severity"`
	Title    string         `json:"title"`
	Evidence []string       `json:"evidence"`
}

// Config tunes the deterministic thresholds (FP control lives here).
type Config struct {
	ImpossibleTravelWindow time.Duration // two diff-country logins within this → impossible travel
	SprayThreshold         int           // failed logins within SprayWindow that trip a spray alert
	SprayWindow            time.Duration
}

func (c Config) withDefaults() Config {
	if c.ImpossibleTravelWindow <= 0 {
		c.ImpossibleTravelWindow = time.Hour
	}
	if c.SprayThreshold <= 0 {
		c.SprayThreshold = 5
	}
	if c.SprayWindow <= 0 {
		c.SprayWindow = 10 * time.Minute
	}
	return c
}

// Detect applies the threat rules to an event stream and returns the threats. Deterministic +
// sorted; each threat is grounded in real events (§10).
func Detect(events []Event, cfg Config) []Threat {
	cfg = cfg.withDefaults()
	byUser := map[string][]Event{}
	for _, e := range events {
		byUser[e.User] = append(byUser[e.User], e)
	}

	var threats []Threat
	for user, evs := range byUser {
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
		threats = append(threats, impossibleTravel(user, evs, cfg)...)
		threats = append(threats, passwordSpray(user, evs, cfg)...)
		for _, e := range evs {
			if e.Type == EventRoleGrant && e.Admin {
				threats = append(threats, Threat{
					Rule: "privileged_grant", User: user, Severity: types.SeverityHigh,
					Title:    fmt.Sprintf("%s was granted a privileged role (%s)", user, nz(e.Detail, "admin")),
					Evidence: []string{ev(e)},
				})
			}
			if e.Type == EventMFARemoved {
				threats = append(threats, Threat{
					Rule: "mfa_removed", User: user, Severity: types.SeverityHigh,
					Title:    fmt.Sprintf("%s had an MFA factor removed (account security downgraded)", user),
					Evidence: []string{ev(e)},
				})
			}
		}
	}
	sort.SliceStable(threats, func(i, j int) bool {
		if threats[i].User != threats[j].User {
			return threats[i].User < threats[j].User
		}
		return threats[i].Rule < threats[j].Rule
	})
	return threats
}

// impossibleTravel: two consecutive SUCCESSFUL logins from DIFFERENT non-empty countries within
// the window. FP guards: same country never fires; an unknown (empty) country never fires (we
// don't guess geo); only successful logins count.
func impossibleTravel(user string, evs []Event, cfg Config) []Threat {
	var logins []Event
	for _, e := range evs {
		if e.Type == EventLogin && e.Country != "" {
			logins = append(logins, e)
		}
	}
	var out []Threat
	for i := 1; i < len(logins); i++ {
		a, b := logins[i-1], logins[i]
		if a.Country != b.Country && b.Time.Sub(a.Time) <= cfg.ImpossibleTravelWindow {
			out = append(out, Threat{
				Rule: "impossible_travel", User: user, Severity: types.SeverityHigh,
				Title: fmt.Sprintf("%s logged in from %s then %s within %s — impossible travel",
					user, a.Country, b.Country, b.Time.Sub(a.Time).Round(time.Minute)),
				Evidence: []string{ev(a), ev(b)},
			})
		}
	}
	return out
}

// passwordSpray: ≥ threshold failed logins for the user inside any SprayWindow. Fires once.
func passwordSpray(user string, evs []Event, cfg Config) []Threat {
	var fails []Event
	for _, e := range evs {
		if e.Type == EventLoginFail {
			fails = append(fails, e)
		}
	}
	for i := range fails {
		count, last := 1, i
		for j := i + 1; j < len(fails); j++ {
			if fails[j].Time.Sub(fails[i].Time) <= cfg.SprayWindow {
				count++
				last = j
			} else {
				break
			}
		}
		if count >= cfg.SprayThreshold {
			return []Threat{{
				Rule: "password_spray", User: user, Severity: types.SeverityMedium,
				Title:    fmt.Sprintf("%s: %d failed logins within %s — possible password spray / brute force", user, count, cfg.SprayWindow),
				Evidence: []string{ev(fails[i]), ev(fails[last])},
			}}
		}
	}
	return nil
}

func ev(e Event) string {
	t := e.Time.UTC().Format(time.RFC3339)
	if e.IP != "" {
		return fmt.Sprintf("%s %s from %s (%s) at %s", e.Type, e.User, e.IP, nz(e.Country, "?"), t)
	}
	return fmt.Sprintf("%s %s %s at %s", e.Type, e.User, e.Detail, t)
}

func nz(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}

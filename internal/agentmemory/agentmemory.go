// Package agentmemory is what the AI engineer is told about THIS customer, and the same list the customer
// sees and edits.
//
// THE GAP. The product stored a great deal the customer had already said — who owns each asset, which
// assets are out of scope and why, which risks they accepted, which proposed fixes they rejected, where
// they said our evidence did not convince them — and the agent was given only the out-of-scope list. So it
// re-proposed a fix style the team had just rejected, raised an accepted risk as urgent, and could not say
// who to route anything to. Nothing new needs collecting; this joins what exists.
//
// ONE builder serves the prompt and the page, so what the agent is told and what the customer can see are
// the same list by construction. A memory the customer cannot inspect is one they cannot correct.
//
// It is CONTEXT, NEVER EVIDENCE. The prompt says so: these lines may shape routing, scope, the fix it
// proposes and how it explains, and may never be cited as proof of a finding or used to hide one. Every
// line names where it came from, so a wrong fact can be fixed at its source rather than argued with here.
package agentmemory

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Kinds of memory line, in the order they are rendered.
const (
	KindNote        = "note"         // the customer's own words
	KindOwner       = "owner"        // asset → owner/team
	KindOutOfScope  = "out_of_scope" // assets excluded, with the reason
	KindDecision    = "decision"     // risk decisions in force (accepted, false positive, won't fix)
	KindDeclinedFix = "declined_fix" // fixes a person rejected or sent back
	KindExplain     = "explain"      // issues where the customer said our evidence did not convince them
)

var kindOrder = []string{KindNote, KindOwner, KindOutOfScope, KindDecision, KindDeclinedFix, KindExplain}

// caps bound each kind, so memory cannot crowd the findings out of the agent's context.
var caps = map[string]int{KindNote: 20, KindOwner: 40, KindOutOfScope: 20, KindDecision: 30, KindDeclinedFix: 20, KindExplain: 20}

const maxLine = 300

// Line is one remembered fact.
type Line struct {
	Kind   string    `json:"kind"`
	Text   string    `json:"text"`
	Source string    `json:"source"` // where it lives, so it is corrected THERE
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at,omitzero"`
	NoteID string    `json:"note_id,omitempty"` // set on customer notes, which are edited here
}

// Memory is the whole set, plus what was left out by the caps (stated, never silent).
type Memory struct {
	Lines   []Line         `json:"lines"`
	Omitted map[string]int `json:"omitted,omitempty"`
}

// Inputs are the stored facts the memory is built from.
type Inputs struct {
	Tenant   platform.Tenant
	Assets   []platform.Asset
	Ignores  []platform.IgnoreRule
	Actions  []platform.Action
	Feedback []platform.Feedback
	Now      time.Time
}

// Build assembles the memory. Deterministic: the same stored facts give the same lines in the same order.
func Build(in Inputs) Memory {
	by := map[string][]Line{}
	add := func(l Line) {
		l.Text = clip(l.Text)
		if l.Text != "" {
			by[l.Kind] = append(by[l.Kind], l)
		}
	}

	notes := append([]platform.AgentNote(nil), in.Tenant.AgentNotes...)
	sort.SliceStable(notes, func(i, j int) bool { return notes[i].At.After(notes[j].At) })
	for _, n := range notes {
		add(Line{Kind: KindNote, Text: n.Text, Source: "agent notes", By: n.By, At: n.At, NoteID: n.ID})
	}

	assets := append([]platform.Asset(nil), in.Assets...)
	sort.Slice(assets, func(i, j int) bool { return assets[i].Target < assets[j].Target })
	targetOf := map[string]string{}
	for _, a := range assets {
		targetOf[a.ID] = a.Target
		owner := strings.TrimSpace(a.Owner)
		team := strings.TrimSpace(a.Team)
		switch {
		case owner != "" && team != "":
			add(Line{Kind: KindOwner, Text: fmt.Sprintf("%s is owned by %s (%s)", a.Target, owner, team), Source: "assets"})
		case owner != "" || team != "":
			add(Line{Kind: KindOwner, Text: fmt.Sprintf("%s is owned by %s", a.Target, owner+team), Source: "assets"})
		}
	}

	ids := make([]string, 0, len(in.Tenant.OutOfScope))
	for id := range in.Tenant.OutOfScope {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ex := in.Tenant.OutOfScope[id]
		subject := targetOf[id]
		if subject == "" {
			subject = id
		}
		txt := subject + " is out of scope"
		if r := strings.TrimSpace(ex.Reason); r != "" {
			txt += " — " + r
		}
		add(Line{Kind: KindOutOfScope, Text: txt + "; do not propose work on it", Source: "products", By: ex.By, At: ex.At})
	}

	ignores := append([]platform.IgnoreRule(nil), in.Ignores...)
	sort.Slice(ignores, func(i, j int) bool { return ignores[i].At.After(ignores[j].At) })
	for _, r := range ignores {
		if !r.Suppresses(in.Now) {
			continue // lapsed decisions are back on the list; remembering them as in force would be wrong
		}
		txt := fmt.Sprintf("issue %s: decided %q", r.IssueKey, r.Reason)
		if n := strings.TrimSpace(r.Note); n != "" {
			txt += " — " + n
		}
		if !r.ExpiresAt.IsZero() {
			txt += " (review by " + r.ExpiresAt.Format("2006-01-02") + ")"
		}
		add(Line{Kind: KindDecision, Text: txt + "; do not raise it as new or urgent", Source: "issues", By: r.By, At: r.At})
	}

	acts := append([]platform.Action(nil), in.Actions...)
	sort.Slice(acts, func(i, j int) bool { return acts[i].ID > acts[j].ID })
	for _, a := range acts {
		rejected := a.Status == platform.ActRejected
		sentBack := strings.TrimSpace(a.Feedback) != ""
		if !rejected && !sentBack {
			continue
		}
		kind, _ := a.Payload["remediation_type"].(string)
		txt := "fix " + quote(a.Title)
		if kind != "" {
			txt += " (" + kind + ")"
		}
		if rejected {
			txt += " was rejected"
		} else {
			txt += " was sent back"
		}
		if f := strings.TrimSpace(a.Feedback); f != "" {
			txt += ": " + f
		}
		who := a.Approver
		if who == "" {
			who = a.ReviewedBy
		}
		add(Line{Kind: KindDeclinedFix, Text: txt + "; do not propose the same fix again unchanged", Source: "approvals", By: who})
	}

	fb := append([]platform.Feedback(nil), in.Feedback...)
	sort.Slice(fb, func(i, j int) bool { return fb[i].At.After(fb[j].At) })
	for _, f := range fb {
		if f.Evidence != platform.EvidenceInsufficient {
			continue
		}
		txt := "issue " + f.IssueKey + ": the customer said our evidence did not show them why"
		if n := strings.TrimSpace(f.Note); n != "" {
			txt += " — " + n
		}
		add(Line{Kind: KindExplain, Text: txt + "; explain it with the concrete evidence", Source: "issues", By: f.By, At: f.At})
	}

	m := Memory{Lines: []Line{}}
	for _, k := range kindOrder {
		ls := by[k]
		if c := caps[k]; len(ls) > c {
			if m.Omitted == nil {
				m.Omitted = map[string]int{}
			}
			m.Omitted[k] = len(ls) - c
			ls = ls[:c]
		}
		m.Lines = append(m.Lines, ls...)
	}
	return m
}

// PromptLines renders the memory for the agent: one line each, tagged with its kind, and a closing line
// naming anything the caps left out so the agent does not assume the list is complete.
func (m Memory) PromptLines() []string {
	out := make([]string, 0, len(m.Lines)+1)
	for _, l := range m.Lines {
		out = append(out, "["+l.Kind+"] "+l.Text)
	}
	if len(m.Omitted) > 0 {
		var parts []string
		for _, k := range kindOrder {
			if n := m.Omitted[k]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, k))
			}
		}
		out = append(out, "(more not shown: "+strings.Join(parts, ", ")+")")
	}
	return out
}

// PromptBlock renders already-rendered lines (PromptLines) with the framing every agent receives. The
// framing IS the safety rule — context, never evidence; never a reason to hide or downgrade a finding — so
// it lives here once rather than being re-typed per agent, where one copy could quietly drift weaker than
// the others. Empty input renders nothing, so an agent with no memory gets a byte-identical prompt.
func PromptBlock(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(PromptFraming)
	for _, line := range lines {
		b.WriteString("- ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// PromptFraming introduces the memory block. Exported so a test can assert every agent carries it.
const PromptFraming = "WHAT THIS CUSTOMER HAS TOLD US — context, NOT evidence. Use it to route work to the named owner, " +
	"keep to their scope, avoid re-proposing a fix they rejected, and explain better where they said our " +
	"evidence did not convince them. Never cite it as proof of a finding, and never use it to hide, drop or " +
	"downgrade one — a finding the scanners reported stays reported:\n"

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ") // one line, no embedded newlines
	if len(s) > maxLine {
		s = s[:maxLine] + "…"
	}
	return s
}

func quote(s string) string {
	if s == "" {
		return "(untitled)"
	}
	return "“" + s + "”"
}

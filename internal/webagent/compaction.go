package webagent

import (
	"fmt"
	"strings"
)

// compaction.go ports the l2 head+summary+tail pattern (Claude Code auto-compact,
// deterministic variant) to the pentester loop. The engagement transcript grows one
// entry per turn and the PROMPT carries all of it — by turn ~15 that is tens of KB,
// which is exactly where free-tier brains stall and even strong ones degrade ("lost
// in the middle"). Like l2's version this is DETERMINISTIC: no extra model call, no
// lossy prose summary written by the thing being summarized. The load-bearing state —
// recorded findings, probed routes, seed status, defenses — is rebuilt from run state
// (cc), not from narrative, so compaction cannot invent or erase evidence (§10).

// compactThreshold is the transcript length that triggers a collapse. Chosen so a
// normal short engagement never compacts (zero behavior change) and a long one
// compacts at most every ~8 turns afterwards.
const compactThreshold = 14

// compactKeep is how many RECENT entries survive verbatim — the observation the
// agent must act on NOW plus immediate context.
const compactKeep = 6

// compactTranscript collapses the older middle of a transcript into one templated
// progress entry rebuilt from live Context state, preserving the first entries
// (task framing) and the most recent ones verbatim. Returns t unchanged when under
// the threshold.
func compactTranscript(t []string, cc *Context) []string {
	if len(t) <= compactThreshold {
		return t
	}
	head := 2
	if len(t) < head+compactKeep+1 {
		return t
	}
	cut := len(t) - compactKeep
	out := make([]string, 0, head+1+compactKeep)
	out = append(out, t[:head]...)
	out = append(out, progressSummary(cut-head, cc))
	out = append(out, t[cut:]...)
	return out
}

// progressSummary rebuilds the only things the narrative needs to preserve — what
// was proven, what was probed, what remains — from grounded run state.
func progressSummary(dropped int, cc *Context) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%d earlier turns COMPACTED. Progress so far:", dropped)
	if len(cc.Findings) > 0 {
		b.WriteString(" PROVEN: ")
		for i, f := range cc.Findings {
			if i >= 8 {
				fmt.Fprintf(&b, "; +%d more", len(cc.Findings)-8)
				break
			}
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s@%s (%s)", f.Class, f.Route, f.Severity)
		}
	} else {
		b.WriteString(" nothing proven yet")
	}
	probed := cc.probedRoutes()
	if len(probed) > 0 {
		fmt.Fprintf(&b, ". %d route(s) already probed — do not re-send identical requests", len(probed))
	}
	if len(cc.Seeds) > 0 {
		b.WriteString(". Seeded classes still to prove-or-clear:")
		for _, s := range cc.Seeds {
			done := false
			for _, f := range cc.Findings {
				if f.Class == s.Class && strings.TrimRight(f.Route, "/") == strings.TrimRight(s.Route, "/") {
					done = true
					break
				}
			}
			if !done {
				fmt.Fprintf(&b, " %s@%s", s.Class, s.Route)
			}
		}
	}
	if len(cc.Defenses) > 0 {
		fmt.Fprintf(&b, ". Defenses hit: %s", strings.Join(cc.Defenses, ", "))
	}
	b.WriteString(". Full detail lives in the evidence transcript, not here.]")
	return b.String()
}

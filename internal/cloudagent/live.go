package cloudagent

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// live.go gives the AI Cloud Security Engineer its first LIVE capability: the ability to ask, mid
// investigation, "is this still true right now?"
//
// Until now the agent reasoned entirely over a snapshot built before it started. That is fine for
// structure (an ARN does not move) but not for the facts a path actually turns on — a security group
// left open, a role still holding admin. Those change, and a snapshot taken hours earlier can be
// wrong in BOTH directions: a path reported as live may already be closed, and a path dismissed as
// closed may have re-opened. Neither is detectable from the snapshot alone.
//
// The capability is deliberately narrow (ADR: read-only, §10). It re-READS current state; it never
// probes, sends traffic, or mutates. The credential enforcement lives beneath this — the role is
// assumed with cloudsafety.SessionPolicy(), which structurally denies mutation and data-contents
// reads — so this interface cannot become a write path even by mistake.

// LiveFact is what a live re-read found about ONE resource. Deliberately SDK-free: cloudagent must
// not import the AWS SDK (the same isolation the *remediate packages keep), so the platform adapts
// its fetcher into this shape rather than handing the agent cloud types.
type LiveFact struct {
	// Covered reports whether the surface this resource lives on was actually read. It is the most
	// important field here: when false, EVERY other field is meaningless. "We did not look" and
	// "it is not there" are different answers, and conflating them is how an agent concludes a
	// resource was deleted because an API call was never made (§10).
	Covered bool
	// Found reports whether the resource exists in the account NOW. Meaningful only when Covered.
	Found bool

	Public     bool
	Privileged bool
	Sensitive  bool

	// Detail is human-readable specifics worth citing in a finding (open ports, attached policy).
	Detail string
	// ReadAt is when the live read happened, so evidence can state its freshness.
	ReadAt string
	// Why explains a non-covered surface ("no IAM permission on the role"), so the agent can report
	// the gap rather than silently reasoning past it.
	Why string
}

// LiveReader re-reads the CURRENT state of the account. Implemented by the platform over its already
// wired read-only fetcher; nil on the Context when no live path is configured, in which case the
// tool says so instead of pretending the snapshot is current.
type LiveReader interface {
	// CheckLive returns the live state of one resource by id (ARN).
	CheckLive(ctx context.Context, id string) (LiveFact, error)
	// Coverage states what the live read did and did not cover, in one line.
	Coverage() string
}

// tCheckLive is the agent's live re-read tool. It answers one question — "is the snapshot still
// right about this resource?" — and is explicit about which of the three possible answers it is
// giving: AGREES, DIFFERS, or COULD NOT CHECK.
func tCheckLive(cc *Context, args map[string]any) string {
	id := argStr(args, "id")
	if strings.TrimSpace(id) == "" {
		return "check_live needs an id (the resource ARN, as it appears in the graph)"
	}
	if cc.Live == nil {
		// Honest degradation, mirroring estate_context: no live path wired is a REAL answer, and a
		// different one from "the snapshot is current".
		return "live re-read is not configured for this run, so the snapshot is all we have. Its facts " +
			"may be stale — say so when you record an issue that depends on a config flag (public, " +
			"privileged) rather than on structure."
	}

	fact, err := cc.Live.CheckLive(context.Background(), id)
	if err != nil {
		return fmt.Sprintf("live re-read failed for %s (%v). The snapshot is unconfirmed for this "+
			"resource — treat its config flags as possibly stale. %s", id, err, cc.Live.Coverage())
	}
	if !fact.Covered {
		why := fact.Why
		if why == "" {
			why = "that surface was not read"
		}
		return fmt.Sprintf("COULD NOT CHECK %s: %s. This is NOT evidence the resource is gone or "+
			"unchanged — nothing was read about it. %s", id, why, cc.Live.Coverage())
	}

	snap := cc.Snap.Node(id)
	if !fact.Found {
		if snap == nil {
			return fmt.Sprintf("LIVE (read %s): no resource %s in the account, and none in the snapshot either.", fact.ReadAt, id)
		}
		// The surface WAS read and the resource is absent — a real, citable change.
		return fmt.Sprintf("LIVE (read %s): %s no longer exists in the account, though the snapshot "+
			"still has it. It was deleted or renamed since the snapshot — any path through it is stale.",
			fact.ReadAt, id)
	}

	live := fmt.Sprintf("public=%v privileged=%v sensitive=%v", fact.Public, fact.Privileged, fact.Sensitive)
	if fact.Detail != "" {
		live += " (" + fact.Detail + ")"
	}
	if snap == nil {
		return fmt.Sprintf("LIVE (read %s): %s exists now — %s — but is NOT in the snapshot. The "+
			"snapshot predates it, so the graph cannot show paths through it; record only what you can "+
			"ground in the graph.", fact.ReadAt, id, live)
	}

	var diffs []string
	if snap.Public != fact.Public {
		diffs = append(diffs, fmt.Sprintf("public: snapshot=%v live=%v", snap.Public, fact.Public))
	}
	if snap.Privileged != fact.Privileged {
		diffs = append(diffs, fmt.Sprintf("privileged: snapshot=%v live=%v", snap.Privileged, fact.Privileged))
	}
	if snapSensitive := cloudgraph.SensitiveData(snap); snapSensitive != fact.Sensitive {
		diffs = append(diffs, fmt.Sprintf("sensitive: snapshot=%v live=%v", snapSensitive, fact.Sensitive))
	}
	if len(diffs) == 0 {
		return fmt.Sprintf("LIVE (read %s): %s — %s. AGREES with the snapshot, so a path through it "+
			"rests on current state.", fact.ReadAt, id, live)
	}
	return fmt.Sprintf("LIVE (read %s): %s — %s. DIFFERS from the snapshot [%s]. The LIVE reading is "+
		"the current truth; re-check whether the path you are building still holds.",
		fact.ReadAt, id, live, strings.Join(diffs, "; "))
}

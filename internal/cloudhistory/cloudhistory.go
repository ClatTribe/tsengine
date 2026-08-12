// Package cloudhistory keeps a timeline of a cloud estate's SECURITY-RELEVANT STATE, so the product can
// answer the first question asked in every incident: WHEN DID THIS CHANGE?
//
// THE GAP THIS CLOSES. cloudsnap stores a tenant's cloud inventory "latest-wins-per-tenant" — its own
// words. That is right for what it was built for (the cloud agent reasoning over current state) and it
// means "when did this bucket become public?" and "when did this identity first get a path to admin?"
// were structurally unanswerable. /v1/cloud/drift could not answer them either: it makes the CALLER post
// both the before and after, so the product held no baseline of its own.
//
// WHY A DIGEST AND NOT A REWIND. The obvious design is to keep N full inventories and let a reader rewind
// the whole graph. It is also the wrong one: cloudsnap describes an inventory as "a large, ephemeral
// blob", and thirty copies per tenant buys storage growth to answer a question that only needs a few
// fields. What actually answers "when did this change" is a per-resource fingerprint of the attributes
// that carry security meaning — public, privileged, sensitivity, type. So that is what is kept, and this
// package is deliberately NARROWER than a time machine: it can tell you when a resource became public,
// and it cannot replay the whole graph as it stood. Saying which of those you have is the difference
// between a useful record and an over-claimed one.
//
// APPEND-ONLY WITH CHANGE DETECTION, the same shape grc/evidence_timeline already proves for compliance
// posture: capture on every pass, skip the write when nothing security-relevant moved, so the timeline
// stays meaningful instead of becoming one row per scan. That package solved this problem for controls
// and was never pointed at the estate.
package cloudhistory

import (
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// ResourceState is the security-relevant attributes of ONE resource at one moment.
//
// Deliberately small. Every field here is something whose CHANGE is a security event; anything whose
// change is merely operational (tags, names, sizes) is left out, because a timeline that records
// everything records nothing a reader can act on.
type ResourceState struct {
	Type       string `json:"type,omitempty"`
	Public     bool   `json:"public,omitempty"`
	Privileged bool   `json:"privileged,omitempty"`
	Sensitive  string `json:"sensitive,omitempty"`
}

// Digest is one capture: what the estate's security-relevant state looked like at CapturedAt.
type Digest struct {
	TenantID   string                   `json:"tenant_id"`
	CapturedAt time.Time                `json:"captured_at"`
	Resources  map[string]ResourceState `json:"resources"`
	// Provider + AccountID identify WHICH estate, so a tenant with two clouds keeps two timelines that
	// never contaminate each other.
	Provider  string `json:"provider,omitempty"`
	AccountID string `json:"account_id,omitempty"`
}

// DigestOf reduces a graph snapshot to its security-relevant state.
func DigestOf(snap *cloudgraph.Snapshot, tenantID, provider, accountID string, at time.Time) Digest {
	d := Digest{
		TenantID: tenantID, CapturedAt: at.UTC(), Provider: provider, AccountID: accountID,
		Resources: map[string]ResourceState{},
	}
	if snap == nil {
		return d
	}
	for _, n := range snap.Nodes {
		if n == nil {
			continue
		}
		d.Resources[n.ID] = ResourceState{
			Type:       n.Type,
			Public:     n.Public,
			Privileged: n.Privileged,
			Sensitive:  string(n.Sensitive),
		}
	}
	return d
}

// Equal reports whether two digests describe the same security state — the change-detection that keeps
// the timeline meaningful. Time is deliberately NOT compared: two captures of an unchanged estate are
// the same state, and recording both would turn the history into a scan log.
func (d Digest) Equal(other Digest) bool {
	if len(d.Resources) != len(other.Resources) {
		return false
	}
	for id, a := range d.Resources {
		b, ok := other.Resources[id]
		if !ok || a != b {
			return false
		}
	}
	return true
}

// Change is one security-relevant transition of one resource, between two captures.
type Change struct {
	ResourceID string    `json:"resource_id"`
	Type       string    `json:"type,omitempty"`
	At         time.Time `json:"at"`
	// What changed, in the reader's terms ("became public", "gained privilege", "appeared").
	What string `json:"what"`
	// From/To carry the raw transition for anyone who needs it.
	From ResourceState `json:"from"`
	To   ResourceState `json:"to"`
}

// Diff returns the security-relevant transitions from prev to cur, oldest-resource-id first for a
// stable read. A resource present in neither, or unchanged, produces nothing.
//
// Grounded (§10): it reports only transitions BETWEEN TWO REAL CAPTURES. It never interpolates what
// happened in the gap — if a bucket was public for an hour between two captures, this cannot see it,
// and does not pretend to. That is why the capture cadence matters and why the caller is told it.
func Diff(prev, cur Digest) []Change {
	var out []Change
	at := cur.CapturedAt

	for id, now := range cur.Resources {
		before, existed := prev.Resources[id]
		switch {
		case !existed:
			// A NEW resource is only interesting where it arrives already exposed or privileged —
			// otherwise every scan of a growing estate is a wall of "appeared".
			if now.Public || now.Privileged {
				out = append(out, Change{ResourceID: id, Type: now.Type, At: at,
					What: "appeared, already " + exposureWords(now), From: ResourceState{}, To: now})
			}
		case before != now:
			if w := transitionWords(before, now); w != "" {
				out = append(out, Change{ResourceID: id, Type: now.Type, At: at, What: w, From: before, To: now})
			}
		}
	}
	// A resource that DISAPPEARED while public/privileged is worth recording: it is either genuinely gone
	// (good) or the collector lost visibility (which must not read as "fixed").
	for id, before := range prev.Resources {
		if _, still := cur.Resources[id]; !still && (before.Public || before.Privileged) {
			out = append(out, Change{ResourceID: id, Type: before.Type, At: at,
				What: "no longer present (removed, or no longer visible to the collector)",
				From: before, To: ResourceState{}})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ResourceID < out[j].ResourceID })
	return out
}

func exposureWords(s ResourceState) string {
	var parts []string
	if s.Public {
		parts = append(parts, "internet-facing")
	}
	if s.Privileged {
		parts = append(parts, "privileged")
	}
	if len(parts) == 0 {
		return "present"
	}
	return strings.Join(parts, " and ")
}

// transitionWords names the change in the terms a reader thinks in, or "" when nothing security-relevant
// moved (a type correction on its own is not a security event).
func transitionWords(before, now ResourceState) string {
	var parts []string
	if !before.Public && now.Public {
		parts = append(parts, "became internet-facing")
	}
	if before.Public && !now.Public {
		parts = append(parts, "no longer internet-facing")
	}
	if !before.Privileged && now.Privileged {
		parts = append(parts, "gained privilege")
	}
	if before.Privileged && !now.Privileged {
		parts = append(parts, "lost privilege")
	}
	if before.Sensitive != now.Sensitive {
		switch {
		case now.Sensitive == "":
			parts = append(parts, "no longer classified sensitive")
		case before.Sensitive == "":
			parts = append(parts, "classified sensitive ("+now.Sensitive+")")
		default:
			parts = append(parts, "sensitivity "+before.Sensitive+" → "+now.Sensitive)
		}
	}
	return strings.Join(parts, ", ")
}

// WhenChanged walks a timeline (oldest first) and returns every security-relevant transition of one
// resource — the literal answer to "when did this bucket become public?".
//
// Returns nothing when the resource never changed, which is a real answer and not a failure: it has been
// in its current state for as long as we have been looking. The caller is responsible for saying that
// honestly rather than rendering an empty list as "no history".
func WhenChanged(timeline []Digest, resourceID string) []Change {
	var out []Change
	for i := 1; i < len(timeline); i++ {
		for _, c := range Diff(timeline[i-1], timeline[i]) {
			if c.ResourceID == resourceID {
				out = append(out, c)
			}
		}
	}
	return out
}

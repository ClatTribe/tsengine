package cloudagent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// fakeLive is a scripted LiveReader.
type fakeLive struct {
	fact LiveFact
	err  error
	cov  string
}

func (f fakeLive) CheckLive(context.Context, string) (LiveFact, error) { return f.fact, f.err }
func (f fakeLive) Coverage() string {
	if f.cov == "" {
		return "Read: s3."
	}
	return f.cov
}

// ctxWith builds an agent Context whose snapshot holds one node with the given flags.
func ctxWith(id string, public, privileged bool, live LiveReader) *Context {
	snap := &cloudgraph.Snapshot{Nodes: map[string]*cloudgraph.Node{}}
	if id != "" {
		snap.Nodes[id] = &cloudgraph.Node{ID: id, Public: public, Privileged: privileged}
	}
	return &Context{Snap: snap, Live: live}
}

const bkt = "arn:aws:s3:::crown"

// THE load-bearing property. A surface that was never read must NOT read as "the resource is gone".
// Conflating them is how an agent concludes a bucket was deleted because an API call was never made
// — it would drop a real attack path on the strength of a call that never happened.
func TestCheckLive_UnreadSurfaceIsNotAbsence(t *testing.T) {
	cc := ctxWith(bkt, true, false, fakeLive{
		fact: LiveFact{Covered: false, Why: "the role cannot list s3", ReadAt: "now"},
		cov:  "Read: iam. NOT read: s3.",
	})
	got := tCheckLive(cc, map[string]any{"id": bkt})

	if !strings.Contains(got, "COULD NOT CHECK") {
		t.Fatalf("an unread surface must report COULD NOT CHECK, got: %s", got)
	}
	if !strings.Contains(got, "NOT evidence") {
		t.Errorf("must say absence here is not evidence of removal, got: %s", got)
	}
	for _, forbidden := range []string{"no longer exists", "was deleted"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("unread surface reported as deletion (%q): %s", forbidden, got)
		}
	}
	if !strings.Contains(got, "cannot list s3") {
		t.Errorf("must carry the reason the surface was unread, got: %s", got)
	}
}

// A surface that WAS read, with the resource absent, is a real and citable change.
func TestCheckLive_ReadSurfaceWithResourceGoneIsADeletion(t *testing.T) {
	cc := ctxWith(bkt, true, false, fakeLive{fact: LiveFact{Covered: true, Found: false, ReadAt: "now"}})
	got := tCheckLive(cc, map[string]any{"id": bkt})
	if !strings.Contains(got, "no longer exists") {
		t.Fatalf("a read surface with the resource absent is a deletion, got: %s", got)
	}
	if !strings.Contains(got, "stale") {
		t.Errorf("should warn the path through it is stale, got: %s", got)
	}
}

// The point of the tool: catch a snapshot that has gone stale on a flag a path depends on.
func TestCheckLive_ReportsDriftAgainstTheSnapshot(t *testing.T) {
	// Snapshot says public; the account says it has been closed since.
	cc := ctxWith(bkt, true, false, fakeLive{fact: LiveFact{Covered: true, Found: true, Public: false, ReadAt: "now"}})
	got := tCheckLive(cc, map[string]any{"id": bkt})
	if !strings.Contains(got, "DIFFERS") {
		t.Fatalf("drift must be reported as DIFFERS, got: %s", got)
	}
	if !strings.Contains(got, "public: snapshot=true live=false") {
		t.Errorf("must name the field that drifted, got: %s", got)
	}

	// And agreement must be stated as agreement, so the agent can lean on it.
	cc2 := ctxWith(bkt, true, false, fakeLive{fact: LiveFact{Covered: true, Found: true, Public: true, ReadAt: "now"}})
	if got2 := tCheckLive(cc2, map[string]any{"id": bkt}); !strings.Contains(got2, "AGREES") {
		t.Errorf("matching state must report AGREES, got: %s", got2)
	}
}

// No live path configured is a REAL answer — "the snapshot is unconfirmed" — never silence that the
// agent would read as "the snapshot is current". Mirrors estate_context's nil handling.
func TestCheckLive_UnconfiguredSaysSoRatherThanImplyingCurrency(t *testing.T) {
	cc := ctxWith(bkt, true, false, nil)
	got := tCheckLive(cc, map[string]any{"id": bkt})
	if !strings.Contains(got, "not configured") {
		t.Fatalf("must say the live path is not configured, got: %s", got)
	}
	if !strings.Contains(got, "stale") {
		t.Errorf("must warn the snapshot may be stale, got: %s", got)
	}
	if strings.Contains(got, "AGREES") {
		t.Errorf("an unconfigured reader must never claim agreement: %s", got)
	}
}

// The capability must be reachable the way the agent actually calls it — through get_resource with
// live:true. A live re-read wired into a tool nobody can invoke would pass every test above and do
// nothing in production (the seam class this campaign kept finding).
func TestGetResource_LiveFlagReachesTheLiveRead(t *testing.T) {
	cc := ctxWith(bkt, true, false, fakeLive{fact: LiveFact{Covered: true, Found: true, Public: false, ReadAt: "now"}})

	plain := tGet(cc, map[string]any{"id": bkt})
	if strings.Contains(plain, "LIVE") {
		t.Errorf("get_resource without live:true must not do a live read: %s", plain)
	}
	withLive := tGet(cc, map[string]any{"id": bkt, "live": true})
	if !strings.Contains(withLive, "DIFFERS") {
		t.Fatalf("get_resource(live:true) must append the live comparison, got: %s", withLive)
	}
	if !strings.Contains(withLive, "moves from here") && !strings.Contains(withLive, "no outgoing edges") {
		t.Errorf("the graph view must still be present alongside the live view: %s", withLive)
	}
}

// A failed live read must not be reported as a clean confirmation.
func TestCheckLive_ErrorIsNotConfirmation(t *testing.T) {
	cc := ctxWith(bkt, true, false, fakeLive{err: errors.New("assume-role denied")})
	got := tCheckLive(cc, map[string]any{"id": bkt})
	if !strings.Contains(got, "failed") || strings.Contains(got, "AGREES") {
		t.Fatalf("a failed read must be reported as unconfirmed, got: %s", got)
	}
}

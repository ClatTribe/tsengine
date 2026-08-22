package platformapi

import (
	"context"
	"net/http"
	"strconv"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/store"
)

// proofqueue.go wires the DOUBT → PROVE edge into the running platform.
//
// pentest.SelectForProof answers "which unproven findings are worth an exploit attempt". This is what
// asks it on every monitoring pass and exposes the answer, so the two agents stop being two tools that
// share a database and start behaving like one engineer: the defensive side surfaces a claim, and the
// offensive side is pointed at it to settle the claim.
//
// WHY IT ONLY PROPOSES. The queue is computed and surfaced; it does not launch engagements by itself.
// Active exploitation is consent-gated (RoE.ActiveAuthorized — an explicit AllowActive, a named
// authorizer, and a recorded consent statement), and a routing convenience must never manufacture
// that consent. So the loop's job is to say "these are the claims worth settling"; a human or an
// already-consented engagement does the settling. Fail-closed by construction: SelectForProof returns
// nothing when the tenant has no ownership-verified targets.

// maxProofBatch bounds what one pass will nominate. A noisy scan must not turn into an unbounded
// exploit campaign, and a human reading the queue needs a list they can actually triage.
const maxProofBatch = 10

// ProofQueue returns the findings whose doubt is worth resolving for this tenant, most severe first.
func (d Deps) ProofQueue(ctx context.Context, tenantID string) []pentest.ProofRequest {
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil
	}
	owned, err := d.ownedTargets(ctx, tenantID)
	if err != nil {
		return nil
	}
	return pentest.SelectForProof(findings, owned, maxProofBatch)
}

// RecordProofQueue runs on every monitoring pass. It records what the offensive side SHOULD settle, so
// the gap between "we found it" and "we proved it" is visible instead of invisible.
//
// Deliberately cheap and side-effect-light: no LLM, no network, no engagement mutation. A pass that
// nominates nothing costs a store read and records nothing.
func (d Deps) RecordProofQueue(ctx context.Context, tenantID string) int {
	// The kill-switch halts autonomous work; nominating targets for exploitation is exactly the kind of
	// thing it exists to stop, even though nothing is executed here.
	if t, err := d.Store.GetTenant(ctx, tenantID); err == nil && t.AgentsHalted {
		return 0
	}
	q := d.ProofQueue(ctx, tenantID)
	if len(q) == 0 {
		return 0
	}
	if d.Recorder != nil {
		targets := make([]string, 0, len(q))
		for _, r := range q {
			targets = append(targets, r.Class+"@"+r.Target)
		}
		d.Recorder.Record("unproven findings nominated for exploitation", "proof_queue",
			map[string]any{"tenant_id": tenantID, "count": len(q), "requests": targets},
			"claims awaiting proof — a scanner finding is a claim until an exploit settles it")
	}
	return len(q)
}

// handleProofQueue (GET /v1/proof-queue) exposes the queue.
//
// This is the surface that makes the two personas legible as one: it answers "what has the engineer
// found that the pentester has not yet settled?", which neither agent could answer on its own.
func (d Deps) handleProofQueue(w http.ResponseWriter, r *http.Request, tenantID string) {
	q := d.ProofQueue(r.Context(), tenantID)
	if q == nil {
		q = []pentest.ProofRequest{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"requests": q,
		"count":    len(q),
		// Stated explicitly so a caller does not read an empty queue as "nothing is unproven": with no
		// ownership-verified target there is nothing we are permitted to probe, which is a different
		// thing from having nothing worth probing.
		//
		// The note is STATE-SPECIFIC and a COMPLETE SENTENCE, because its only consumer appends it to
		// prose ("Nothing is queued for proof. " + note). It used to be a single definition fragment
		// beginning lowercase, so the empty state rendered "Nothing is queued for proof. unproven
		// high/critical findings whose class an offensive driver can demonstrate." — which reads as a
		// truncation, and asserts what the queue HOLDS in the one state where it holds nothing. The
		// ownership caveat, the whole reason this field exists, came third behind that confusion.
		"note":      proofQueueNote(len(q)),
		"max_batch": strconv.Itoa(maxProofBatch),
	})
}

// proofQueueNote is the caveat for the queue's CURRENT state. Both variants are complete sentences
// that read correctly when a caller appends them to its own prose, and each is true only of the
// state it describes — so a consumer cannot render a sentence that is false for what it is showing.
func proofQueueNote(n int) string {
	if n == 0 {
		return "That can mean nothing high or critical is left unsettled — or that no target has " +
			"verified ownership yet, so there is nothing we are permitted to probe. Verify asset " +
			"ownership to enable proof."
	}
	return "Each entry is an unproven high or critical finding whose class an offensive driver can demonstrate."
}

package l2

import (
	"context"
	"fmt"
	"strings"
)

// tools_engineer.go turns the Lead from an ANALYST into an ENGINEER.
//
// THE GAP THIS CLOSES. Audit the pre-existing catalogue by what each tool actually does:
//
//	get_finding, investigate_cloud, investigate_code, lookup_compliance_mapping,
//	query_threat_intel, send_request                     → read
//	update_finding, create_vulnerability_report,
//	record_hypothesis                                    → write to OUR store
//	advance_phase, finish_scan                           → agent state
//
// Not one of them changes anything in the customer's world. The agent could read, reason and write a
// report — and then stop. Every actual change came from the deterministic remediate.Propose path,
// which the agent has no connection to. So the human-in-the-loop had nothing from the agent to
// approve, because the agent never proposed anything.
//
// That is the difference between an analyst and an engineer, and it is why the persona under-delivers:
// an engineer's defining property is that they CHANGE THINGS. A security engineer who can only write
// reports is a security analyst.
//
// THE MODEL IS CLAUDE CODE'S, deliberately. The agent works the problem autonomously with a tool belt
// — search the estate, propose a fix, ask for proof, check whether a fix held, raise a ticket — and
// the human's role collapses to APPROVING SIDE EFFECTS. Not choosing which tool to run, not clicking
// "investigate" per finding: approving a diff, exactly like approving an edit in an agentic editor.
//
// EVERY SIDE EFFECT STILL GOES THROUGH THE EXISTING GATE. propose_fix does not apply anything — it
// creates a platform.Action that lands at the HITL desk under the same tier rules, kill-switch and
// signed ledger as a deterministically-proposed one. The agent gains a voice, not authority (§18.2
// inv. 3 is untouched). That is what makes it safe to let it act autonomously: the blast radius of a
// wrong proposal is a human reading a bad diff.

// EstateSearch answers "what do I have?" over the tenant's own findings and assets.
//
// This is the tool a security engineer reaches for most and the one the product never had: no
// endpoint answered "are we affected by X?" or "which assets have unproven criticals?". Without it
// the agent can only reason about findings someone already handed it, which is not how the job works.
type EstateSearch interface {
	Search(ctx context.Context, query string) (summary string, err error)
}

// FixProposer creates a remediation for a human to approve. It NEVER applies.
//
// Returns the queued action's id so the agent can refer to it, and so the run's trail shows what it
// actually proposed rather than what it merely suggested in prose.
type FixProposer interface {
	ProposeFix(ctx context.Context, findingID, rationale string) (actionID string, err error)
}

// ProofRequester hands an unproven finding to the offensive agent to settle.
//
// This is the doubt→prove edge exposed as a tool. It matters because it is the one way the engineer
// can resolve "is this real?" with evidence rather than opinion — and false-positive judgement is
// measurably the thing models are worst at (an 8B general and an 8B security model over-attributed
// non-vulnerabilities 2/6 and 6/6 of the time). An exploit attempt is a deterministic test where the
// model's opinion is only a guess.
type ProofRequester interface {
	RequestProof(ctx context.Context, findingID string) (summary string, err error)
}

// FixVerifier answers "did the fix actually hold?" from the re-test record.
//
// An engineer who proposes fixes and never checks them is not doing the job; this closes the loop the
// agent otherwise leaves open.
type FixVerifier interface {
	VerifyStatus(ctx context.Context, actionID string) (summary string, err error)
}

// TicketFiler raises work that is not ours to do — the productivity half of the tool belt. Plenty of
// real remediation is somebody else's change; being unable to hand it over means the agent silently
// drops it.
type TicketFiler interface {
	FileTicket(ctx context.Context, title, body string) (ref string, err error)
}

// EngineerTools builds the act-on-the-world half of the catalogue.
//
// Each is nil-safe: an unwired capability yields a tool that SAYS it is unavailable rather than one
// that silently no-ops or, worse, claims success. A deployment without a ticketing connector must not
// have an agent that believes it filed a ticket.
func EngineerTools(search EstateSearch, fixer FixProposer, prover ProofRequester, verifier FixVerifier, filer TicketFiler) Catalog {
	var out Catalog

	out = append(out, Tool{
		Schema: ToolSchema{
			Name: "search_estate",
			Description: "Search this tenant's own findings and assets in plain language — e.g. " +
				"'unproven critical findings on internet-facing assets' or 'anything mentioning log4j'. " +
				"Use it to establish what you are dealing with before proposing anything.",
			Params: obj(map[string]any{
				"query": str("what to look for, in plain language"),
			}, "query"),
		},
		Handler: func(ctx context.Context, args map[string]any, _ *State) (ToolResult, error) {
			q := engArg(args, "query")
			if q == "" {
				return ToolResult{Content: "search_estate needs a query."}, nil
			}
			if search == nil {
				return ToolResult{Content: "Estate search is not available in this deployment."}, nil
			}
			s, err := search.Search(ctx, q)
			if err != nil {
				return ToolResult{Content: "Search failed: " + err.Error()}, nil
			}
			return ToolResult{Content: s}, nil
		},
	})

	out = append(out, Tool{
		Schema: ToolSchema{
			Name: "propose_fix",
			Description: "Propose a concrete remediation for a finding. This does NOT apply anything — " +
				"it queues the change for a human to approve, exactly like proposing an edit. Give the " +
				"rationale you would give a colleague reviewing it.",
			Params: obj(map[string]any{
				"finding_id": str("the finding this fixes — it must be one you have actually seen"),
				"rationale":  str("why this fix, in one or two sentences"),
			}, "finding_id"),
		},
		Handler: func(ctx context.Context, args map[string]any, _ *State) (ToolResult, error) {
			id := engArg(args, "finding_id")
			if id == "" {
				return ToolResult{Content: "propose_fix needs a finding_id."}, nil
			}
			if fixer == nil {
				return ToolResult{Content: "Fix proposal is not available in this deployment."}, nil
			}
			actID, err := fixer.ProposeFix(ctx, id, engArg(args, "rationale"))
			if err != nil {
				// A refusal is usually grounding doing its job — an unknown finding id, or a class with
				// no remediation path. Say so plainly so the agent stops rather than retrying blindly.
				return ToolResult{Content: "Could not propose a fix: " + err.Error()}, nil
			}
			return ToolResult{Content: fmt.Sprintf(
				"Queued %s for human approval. It is NOT applied — a reviewer will approve, request "+
					"changes, or reject it.", actID)}, nil
		},
	})

	out = append(out, Tool{
		Schema: ToolSchema{
			Name: "request_proof",
			Description: "Ask the offensive agent to try to actually exploit a finding you are unsure " +
				"about. A successful exploit proves it; a failed attempt proves nothing either way. Use " +
				"this instead of guessing whether something is a false positive.",
			Params: obj(map[string]any{
				"finding_id": str("the unproven finding to settle"),
			}, "finding_id"),
		},
		Handler: func(ctx context.Context, args map[string]any, _ *State) (ToolResult, error) {
			id := engArg(args, "finding_id")
			if id == "" {
				return ToolResult{Content: "request_proof needs a finding_id."}, nil
			}
			if prover == nil {
				return ToolResult{Content: "Proof requests are not available in this deployment."}, nil
			}
			s, err := prover.RequestProof(ctx, id)
			if err != nil {
				return ToolResult{Content: "Could not request proof: " + err.Error()}, nil
			}
			return ToolResult{Content: s}, nil
		},
	})

	out = append(out, Tool{
		Schema: ToolSchema{
			Name:        "check_fix_status",
			Description: "Check whether a previously applied fix actually closed the finding, per the re-test record.",
			Params: obj(map[string]any{
				"action_id": str("the remediation to check"),
			}, "action_id"),
		},
		Handler: func(ctx context.Context, args map[string]any, _ *State) (ToolResult, error) {
			id := engArg(args, "action_id")
			if id == "" {
				return ToolResult{Content: "check_fix_status needs an action_id."}, nil
			}
			if verifier == nil {
				return ToolResult{Content: "Fix verification is not available in this deployment."}, nil
			}
			s, err := verifier.VerifyStatus(ctx, id)
			if err != nil {
				return ToolResult{Content: "Could not check the fix: " + err.Error()}, nil
			}
			return ToolResult{Content: s}, nil
		},
	})

	out = append(out, Tool{
		Schema: ToolSchema{
			Name: "open_ticket",
			Description: "Raise a ticket for work that is not ours to change directly — a vendor fix, a " +
				"decision someone else owns, an upgrade that needs planning.",
			Params: obj(map[string]any{
				"title": str("a one-line summary"),
				"body":  str("what needs doing and why it matters"),
			}, "title"),
		},
		Handler: func(ctx context.Context, args map[string]any, _ *State) (ToolResult, error) {
			title := engArg(args, "title")
			if title == "" {
				return ToolResult{Content: "open_ticket needs a title."}, nil
			}
			if filer == nil {
				return ToolResult{Content: "Ticketing is not connected in this deployment — no ticket was filed."}, nil
			}
			ref, err := filer.FileTicket(ctx, title, engArg(args, "body"))
			if err != nil {
				return ToolResult{Content: "Could not file the ticket: " + err.Error()}, nil
			}
			return ToolResult{Content: "Filed " + ref + "."}, nil
		},
	})

	return out
}

// engArg reads a string argument and TRIMS it. The shared argStr deliberately does not, but for these
// tools a whitespace-only value is a model slip rather than a real argument — passing "   " through to
// a search or a fix proposal turns a correctable mistake into a confusing backend call.
func engArg(args map[string]any, key string) string {
	s, _ := args[key].(string)
	return strings.TrimSpace(s)
}

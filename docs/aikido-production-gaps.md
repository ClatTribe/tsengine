# Production readiness vs Aikido — the AI capabilities

Grounded analysis of what ships today vs what Aikido sells, and what's missing to be production-ready.
Every claim below was checked against the code, not assumed.

## What Aikido sells (public pricing/product, July 2026)

| | Aikido |
|---|---|
| **AI AutoFix** | Headline feature on **every** tier. "High-confidence **fix PRs** for confirmed issues." Free: 10/mo. Paid: unlimited. |
| **AI SAST** | AI-based autofixes + AI false-positive reduction, all tiers. |
| **AI Pentesting** | Sold separately ("Attack" suite): Standard €3,500–$4,000, Rightsized €800–€25,000+, Continuous custom. Positioned as "automatically pentest & fix vulnerabilities in every release", business-logic coverage, **audit-grade pentest reports**. |
| Tiers | Developer (free) → Basic $300 → Pro $600 → Advanced $600 → Enterprise. |

## Where we stand — verified against the code

| Capability | Us (verified) | Gap |
|---|---|---|
| **AI Pentester** | **Built**: engagements + Rules-of-Engagement guard + consent gate + active exploitation with machine-checked predicates + VAPT report + named human sign-off. | **At/ahead of parity.** Aikido charges €3.5k+ per pentest; ours is continuous. Marketing under-sells this. |
| **AI autofix — generates a fix** | `POST /v1/findings/{id}/autofix` exists (explicit Snyk/Aikido parity). | Partial — see below. |
| **AI autofix — reads the real source** | ❌ `buildAutofixPrompt` uses **only finding metadata** (rule, CWE, file:line, description, raw output). Its own prompt says "if the exact code isn't shown, give the precise, minimal pattern". | **Real gap** — it returns *advice with a snippet*, not an applicable patch. |
| **AI autofix — verified before delivery** | ❌ production autofix is a single LLM call, unverified. The verified path (`codeagent.ProposePatch` + execution oracle + refine loop) is **benchmark-only** (referenced only by `tsbench`). | **Real gap** — Aikido claims "high-confidence"; ours is unchecked. |
| **AI autofix — lands as a fix PR** | ❌ *was* impossible: the GitHub connector had **zero** Git Data API calls; `Apply` only did `POST /pulls` with a `head` branch something else had to create. | **CLOSED — see below.** |
| **Free-tier AI** | 0 operator-funded (economic invariant: Free must never spend our LLM budget). **But** `resolveAgentLLM` allows a tenant's **own key on any plan** (§18.5) — that costs us nothing. | Different model, arguably better: no AI markup, bring your own key. |

## The fix-delivery chain — the core production gap

The engineer can write a fix and (in the benchmark) we can verify it — but nothing connected that fix
to the customer's repo. Four links; the third is now built:

1. **Read the real source** → autofix must load the file, not work from finding metadata. *(open)*
2. **Propose a verified patch** → route production autofix through `codeagent.ProposePatch` + the
   execution oracle + refine loop instead of its own one-shot metadata prompt. *(open)*
3. **Commit it** → **BUILT** (`GitHub.CommitFiles`): Git Data API blobs → tree → commit → new branch
   ref, then `Apply` opens the PR from that branch, so a fix PR carries a **real diff**. Multi-file
   fixes land as one atomic commit; deterministic blob order; refuses an empty patch; back-compat
   preserved (no `files` → the old prose-PR path). Needs the GitHub App **`contents: write`** scope —
   without it GitHub answers 403 and we surface it honestly (never a silent "fixed").
3. **Verify before the PR** → re-run the scanner on the patched tree + the repo's tests, so the PR is
   "high-confidence" rather than hopeful. `retest.Verify` exists but runs *post-apply* on the next
   scan — it can't gate the PR. *(open)*

Everything stays HITL-gated (§18.2 inv. 3): a fix PR is a proposal a human reviews and merges, never a
direct write to the default branch.

## The one remaining link — and the design decision it needs

Built and tested: **FetchFile** (read real source) → **codeagent.ProposePatch** (already on main) →
**remediate.ProposeWithPatch** (carry the patch) → **CommitFiles + Apply** (commit + PR). What's left
is wiring them together, and that is a design decision rather than glue, because of two seams:

- **A `types.Finding` carries no `AssetID`.** Findings aren't linked to their asset in the data model;
  everywhere else (per-asset compliance, data-tier) attributes a finding to an asset *heuristically*
  (longest literal target match on the endpoint). A fix PR needs to know the repo — so it needs either
  that same heuristic or a real finding→asset link.
- **Token resolution lives on `runner`, not `platformapi.Deps`.** A handler (`POST /v1/findings/{id}/
  autofix`) has the per-tenant LLM but no `Tokens`; the runner has `Tokens` + the asset + connection
  but no LLM seam. Its `ProposeBatch` injection point (`cmd/platform/main.go`) has the signature
  `func([]types.Finding, platform.Asset) []platform.Action` — no `ctx`, no model.

So the choice is: (a) give `platformapi.Deps` a `Tokens` resolver and generate the patch in the
autofix handler (the fix becomes on-demand, per finding, user-triggered), or (b) widen the
`ProposeBatch` seam with a ctx + LLM and generate patches during the scan→propose pass (fixes arrive
automatically, matching Aikido's "AutoFixes/mo" model). (b) is closer to the competitor's product
shape; (a) is the smaller change and keeps LLM spend user-initiated. **Not chosen unilaterally** —
it changes when we spend a customer's model budget.

## Known product limitation

`ProposePatch` returns **whole-file** contents. Fine for a small module; it breaks down on large files
(token limits, and it risks rewriting untouched code). Diff/hunk-level output or targeted context is
needed before this is safe on real repositories.

## Honest summary

- **AI Pentester**: production-ready and under-marketed vs a competitor charging €3.5k+ per pentest.
- **AI Security Engineer (fix)**: generates advice today. To match "high-confidence fix PRs" it needs
  source-reading + the verified propose/refine path + pre-PR verification. The commit path — the piece
  that made all of it impossible — is now built.

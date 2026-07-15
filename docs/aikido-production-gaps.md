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

## The chain — now complete (`POST /v1/findings/{id}/fix-pr`)

finding → **FetchFile** (real source) → **codeagent.ProposePatch** → **remediate.ProposeWithPatch**
(carries the files) → **Submitter** (the HITL desk) → on approval **CommitFiles + Apply** (commit +
PR with a diff). `/autofix` remains the cheap advice view.

**User-triggered by design** (the product call): a fix spends the customer's OWN model budget
(§18.5 BYO-key), so it runs when they click Fix — never silently on a scan. The automatic
"AutoFixes/mo" shape stays available by widening the runner's `ProposeBatch` seam (it currently has
no ctx/LLM) later.

Two seams shaped the design, and both are handled honestly rather than guessed around:
- **A `types.Finding` carries no `AssetID`**, and a code finding's endpoint is a `file:line` that does
  NOT name the repo — so the usual longest-target attribution cannot identify the codebase. Rather
  than guess which repo to open a PR against: explicit `asset_id` wins → a single connected repo is
  unambiguous → otherwise refuse and ask.
- **Token resolution lives on `runner`, not `platformapi.Deps`** — but `Deps.Runner.Tokens` already
  reaches it, so no new dependency was needed.

## Production readiness — the state after this campaign

| Gap | State |
|---|---|
| **Billing — the product could not take money** | ✅ **Built.** `Tenant.Plan` was set at creation and never changed again: no provider, no checkout, no upgrade path. Now `internal/billing` (catalog to the paise, 18% GST, ₹-native) + `POST /v1/billing/checkout` + a signature-verified `POST /v1/billing/webhook` that is the only thing which flips a plan. Fails closed everywhere; only captured money grants a plan. |
| **Checkout UI** | ✅ **Built.** Settings → "Plan & billing". The browser never flips the plan — Razorpay's signed webhook does, server-side. |
| **Free + own-key leak** | ✅ **Closed.** The agents are the product, so `PlanLimits.AIAgents` (may you run them at all — Free=false) is now distinct from `AIEnabled` (do *we* fund the model — Enterprise only). Free is refused even with its own key. |
| **"Fix it" button** | ✅ **Built.** The finding page leads with the real fix PR; the advice view is the fallback. |
| Razorpay account + GST registration | ⏳ **Yours** — the live half is credential-gated (`RAZORPAY_*`). |
| GitHub App `contents: write` | ⏳ **Yours** — without it the commit 403s (surfaced honestly). |
| Pre-PR verification | ⏳ Needs CI/sandbox to run a customer's tests — see below. |
| Detection quality at scale | ⏳ Needs deployed targets / an autonomous key. The real risk under every claim. |

## What still separates us from "high-confidence fix PRs"

1. **The production patch is UNVERIFIED.** `ProposePatch` runs single-shot here. The
   propose→verify→**refine** loop and the execution oracle exist (`ProposePatchIterative`, benchmarked
   on real CVEs) but on the benchmark branch — wiring them for a *customer* repo means running their
   tests / re-scanning the patched tree, which needs CI or a sandbox. Until then the PR is a
   well-grounded proposal a human must review, not a verified fix.
2. **No UI yet** — the endpoint exists; a "Fix it" button on a finding does not.
3. **`contents: write`** on the GitHub App is required for the commit; a 403 surfaces honestly.

## Known product limitation

`ProposePatch` returns **whole-file** contents. Fine for a small module; it breaks down on large files
(token limits, and it risks rewriting untouched code). Diff/hunk-level output or targeted context is
needed before this is safe on real repositories.

## Honest summary

- **AI Pentester**: production-ready and under-marketed vs a competitor charging €3.5k+ per pentest.
- **AI Security Engineer (fix)**: generates advice today. To match "high-confidence fix PRs" it needs
  source-reading + the verified propose/refine path + pre-PR verification. The commit path — the piece
  that made all of it impossible — is now built.

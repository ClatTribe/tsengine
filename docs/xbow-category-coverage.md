# XBOW category coverage — per-vuln-class performance + the change each gap needs

_Iteration doc for the "test + improve against the XBOW 104" loop. Grounded in the
authoritative benchmark `tags`/`level` metadata (`validation-benchmarks/benchmarks/*/benchmark.json`)
cross-referenced against the durable capture ledger (`bench/xbow-ledger.jsonl`). Updated as the loop
progresses — every number is real, never estimated (§10)._

## Honesty framing (read first)

- **The suite is 104 benchmarks. ~30 are EOL-unbuildable** (dead Debian buster / php5 / node:14 / mysql:5.7 base images — `apt`/registry archived) and are the user-excluded set. So the **addressable set is ~74**.
- **The capture number reflects the ENGINE's exploit primitives driven by a strong brain.** These runs use the file-relay proxy (a frontier model as the agent's brain; the customer supplies their own key in production). A weaker customer model would score lower — the number measures *what the engine makes groundable*, not a fixed product SLA.
- **A benchmark is a single-container, one-flag, known-vuln-present CTF target.** It proves *depth per class*; it does **not** prove breadth/recall on a sprawling real app. Real VAPT value = coverage × depth; this doc measures depth.
- **A category counts as a real capability only when the finding is grounded FP-free** (a deterministic indicator backs it), never when the LLM merely asserts it. That discipline (better than XBOW's "no false positives" bar) is why some categories are deliberately *not* auto-grounded — see the boundary section.

## Overall standing

| | Count |
|---|---|
| Distinct captures (flag-graded, blind flag) | **33 / 104** |
| Tested but not solved | 10 |
| Errored (build-rot, EOL bases) | 5 |
| **Never attempted** | **56** (dominated by the XSS category — see below) |

## Per-category performance matrix

Authoritative tag counts across all 104 (a benchmark can carry multiple tags, so columns sum > 104):

| Category (tag) | Total | Captured | Miss | Errored | **Untested** | Grounding status |
|---|---:|---:|---:|---:|---:|---|
| **xss** | 23 | 0 | 0 | 0 | **23** | engine-capable, **never run** ← #1 gap |
| default_credentials | 18 | 5 | 2 | 0 | 11 | `try_default_creds` (grounded) |
| idor | 15 | 5 | 1 | 1 | 8 | **`bola_probe`** (grounded #879) |
| privilege_escalation | 14 | 2 | 0 | 2 | 10 | **`privesc_probe`** (grounded #881) — untested since |
| ssti | 13 | 7 | 1 | 1 | 4 | `ssti_eval` (grounded) — strong |
| command_injection | 11 | 2 | 3 | 1 | 5 | `cmd_output` + OOB (grounded) |
| business_logic | 7 | 1 | 0 | 0 | 6 | LLM-reasoning, **not FP-free-groundable** |
| sqli | 6 | 5 | 0 | 0 | 1 | `sql_error` + sqlmap (grounded) — strong |
| insecure_deserialization | 6 | 3 | 1 | 0 | 2 | grounded via `cmd_output`/RCE |
| lfi | 6 | 3 | 2 | 1 | 0 | `file_disclosure` (grounded) — exhausted |
| information_disclosure | 6 | 3 | 0 | 1 | 2 | grounded (source/config leak) |
| arbitrary_file_upload | 6 | 2 | 2 | 0 | 2 | upload→LFI/RCE chain (grounded) |
| path_traversal | 5 | 1 | 1 | 2 | 1 | `file_disclosure` (grounded) |
| cve | 4 | 0 | 1 | 2 | 1 | nuclei/wpscan — mostly EOL-errored |
| jwt | 3 | 0 | 0 | 1 | 2 | `jwt_crack` (grounded) — untested |
| graphql | 3 | 1 | 0 | 0 | 2 | introspect + arg-SQLi (grounded) |
| ssrf | 3 | 3 | 0 | 0 | 0 | `oob_interaction` (grounded) — exhausted |
| blind_sqli | 3 | 1 | 1 | 0 | 1 | `slow_response` + sqlmap (grounded) |
| xxe | 3 | 2 | 0 | 0 | 1 | `file_disclosure` (grounded) |
| crypto | 3 | 0 | 0 | 0 | 3 | strong-secret/padding-oracle — **hard-tail** |
| brute_force | 2 | 0 | 0 | 0 | 2 | hydra (grounded) — untested |
| ssh | 1 | 1 | 0 | 0 | 0 | `ssh_exec` (grounded) — exhausted |
| http_method_tamper | 1 | 0 | 0 | 0 | 1 | **no indicator** — needs a feature |
| smuggling_desync | 1 | 0 | 0 | 0 | 1 | request-smuggling — **specialist gap** |
| race_condition | 1 | 0 | 0 | 0 | 1 | **no indicator** — needs a deliberate probe |
| nosqli | 1 | 0 | 0 | 0 | 1 | **no indicator** — needs a feature |

## What change each gap needs (the rule-4 analysis)

Three honest buckets — a coverage gap (just run it), an FP-free feature gap (build a grounded probe), or a correct boundary (not cleanly groundable, leave it to the LLM/operator config).

### A. Coverage gaps — engine can already do it, we just never ran them

- **xss (23 untested) — THE priority.** Mechanic (verified from `XBEN-047/src/app.py` + `check.js`): the app exposes a reflection sink (e.g. `/page?url=`), runs a **server-side PhantomJS bot synchronously**, and if `alert('XSS')` fires it returns *"Here is the flag: …" in the same HTTP response*. No OOB, no external admin-bot to reach. The webagent already has the primitives: `reflected_input` detection + iterative payload crafting + reading the flag from the response body (and `browser_render`/`js_executed` for DOM cases). **Change needed: RUN them.** A light, non-overfit guidance nudge (target the reflection sink; the win string is literally `alert('XSS')`; the flag returns in-band) may lift the per-benchmark-filter cases, but no new detector — forcing an XSS-specific detector would be overfitting (rule 1).
- **privilege_escalation (10 untested).** `privesc_probe` (#881) landed *after* these were last attempted. **Change needed: re-run** — the new grounded self-privesc/mass-assignment tool should now capture a share.
- **jwt (2), brute_force (2), default_credentials (11), command_injection (5).** Grounded tools exist (`jwt_crack`, hydra via `dispatch_oss`, `try_default_creds`, `cmd_output`+OOB). **Change needed: run them**; for filtered-cmdi, the OOB/self-exfil path already shipped.

### B. FP-free feature gaps — a grounded probe is buildable (deliberate, not rushed)

- **race_condition (1).** Groundable FP-free by a **serial-vs-concurrent success-count differential**: fire N identical state-changing requests concurrently; if successes exceed the serially-observed limit, it's a proven TOCTOU. Observed-count, no policy input → no FP. Design carefully (success signal, concurrency) like `bola_probe`/`privesc_probe` — a candidate `race_probe`.
- **nosqli (1).** A NoSQL-injection indicator (operator/`$where`/`$ne` differential — a boolean-true vs boolean-false response divergence, the `sql_error`/blind-sqli analog for Mongo). Groundable, a small detector.
- **http_method_tamper (1).** A method-override differential (a route that 403s on GET but succeeds on a tampered verb/`X-HTTP-Method-Override`). Groundable as an authz-bypass differential.

### C. Correct boundaries — not FP-free-groundable, leave them where they belong

- **business_logic (6 untested).** Intent-dependent; "this flow is abusable" is the LLM's reasoning job, not a deterministic indicator. Forcing one would be FP-prone. Stays open-ended L2 reasoning.
- **general BFLA (function-level, distinct from self-privesc).** "This function is privileged" is a policy fact responses can't prove — stays `apiauthz`'s operator-configured `api`-asset job.
- **crypto (3).** Strong-secret / padding-oracle hard-tail; `padbuster` covers the oracle case where present, but the modern-crypto ones are genuinely infeasible (documented, grind-forbidden).
- **smuggling_desync (1), cve (mostly errored).** Request-smuggling needs a specialist detector on EOL stacks; the `cve` tail is dominated by build-rot, not detection gaps.

## VAPT relevance (per the honesty rule)

The grounded classes above are the exact primitives an SMB/enterprise engagement is judged on — and the two most recent additions map straight to the OWASP API Top-10: **`bola_probe` = API#1 (BOLA)**, **`privesc_probe` = API#3 (BFLA, self-slice) + API#6 (mass-assignment)**. Closing the **xss** coverage gap adds the single most common web-app finding class. The buckets are honest about the ceiling: breadth on real (non-CTF) targets and the policy-dependent classes are the frontier, not more flag counts.

## Iteration log

- **2026-07-06** — built this matrix from authoritative tags. Surfaced the **xss blind spot** (23/104, largest category, 0 attempted — a *coverage* gap, engine is capable; the flag returns in-band from a server-side bot). Confirmed `privilege_escalation` has 10 untested benchmarks now addressable by the fresh `privesc_probe`. Named the FP-free feature candidates (`race_probe`, nosqli, method-tamper) and the correct boundaries (business_logic, general BFLA, crypto). Next loop action: **drive the untested xss + privilege_escalation sets** for real performance numbers.

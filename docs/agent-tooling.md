# Agent tooling — what each L2 agent uses, and why tools load only when needed

This is the harness-engineering contract for the two L2 agents. The governing principle (CLAUDE.md §2.6,
Invariant L2-CAP): **the number of tools the LLM sees at any moment is minimal — past ~12, tool-use
accuracy degrades steeply.** So each agent shows the model only the tools usable *right now*, and the L1
OSS tools are reached through a single gateway slot, never enumerated to the model.

## Three ways a tool reaches (or doesn't reach) the LLM

1. **Deterministic L1 prepass — the LLM never sees these.** The anchor/fan-out OSS scanners (nuclei,
   sqlmap, semgrep, trivy, prowler, …) fire deterministically before the agent runs. They're always-on
   coverage, not a choice the model makes — so they cost zero tool-slots.
2. **The gateway slot — many tools, one slot.** Specialised OSS is reached via ONE catalog entry:
   `dispatch_oss` (offensive agent → sqlmap/wpscan/nuclei/ffuf/hydra/padbuster in the sandbox) and
   `dispatch_l2_probe` (the L2 Lead → the whole registry tier). The model picks a tool *by argument*, so
   the visible catalog stays small no matter how many OSS tools exist behind it.
3. **Progressive disclosure — the direct tools the agent drives.** The remaining tools are shown as a
   MINIMAL, state-relevant subset per turn (below), not the full catalog.

## AI offensive agent (`internal/webagent`) — 24 tools, progressively disclosed

The catalog is grouped; `selectTools(cc)` (`toolselect.go`) shows the group only when the world-model
(ADR 0016) says it's relevant. Active list is ~7 at recon vs 24 before.

| Group | Tools | Shown when |
|---|---|---|
| **core** | `send_request`, `list_routes`, `record_finding`, `note_defense`, `finish` | always |
| **recon** | `discover_content`, `graphql_introspect` | surface still thin (<8 endpoints, or no params yet) |
| **probe** | `sqli_bool_probe`, `nosqli_probe`, `bola_probe`, `session_idor_probe`, `privesc_probe`, `tamper_probe`, `race_probe`, `cors_probe`, `dispatch_oss` | there IS surface to attack (≥1 endpoint) |
| **blind** | `oob_url`, `oob_check`, `browser_render` | with the probes (blind/DOM classes) |
| **cred** | `jwt_crack`, `crack_hash`, `try_default_creds` | a credential/hash/token appears in evidence |
| **lateral** | `ssh_exec` | with the cred signals (leaked-cred SSH hop) |
| **confirm** | `confirm_exploit` | once a finding is recorded |

Why aggressive phasing here: the offensive catalog is 2× the cap, and the phases are genuinely disjoint —
a recon turn has no use for `crack_hash`, and `ssh_exec`/`confirm_exploit` are meaningless until creds or a
finding exist. Hiding them until their trigger keeps the model focused and its tool-calls accurate.

## AI security engineer (`internal/cloudagent`) — 12 tools, lightly gated

| Tool | Role | Shown when |
|---|---|---|
| `list_resources`, `get_resource`, `get_findings` | orient over the inventory | always |
| `resolve_access`, `find_paths`, `blast_radius`, `detect_privesc`, `enumerate_attack_paths` | analyse reachability / impact | always |
| `record_issue` | commit a grounded attack path | always |
| `rightsize_principal` | CIEM over-privilege | only when a principal carries observed usage data (else it no-ops) |
| `propose_fix` | applyable, cloudiam-verified remediation | only once ≥1 issue is recorded (nothing to fix before that) |
| `finish` | end + summary | always |

Why LIGHT gating here (vs the offensive agent): the cloud engineer's catalog is a **cohesive 12-tool
reasoner already at the cap** — its analysis tools apply throughout an investigation, so over-phasing them
would hurt. Only two tools have a real precondition; gating them is correct, not arbitrary.

## Safety invariant (both agents)

Disclosure narrows only what the LLM **sees**. The dispatch registry keeps **every** tool, so a tool
called out-of-phase still works — progressive disclosure is an accuracy optimisation, never a capability
gate (both agents have a test asserting the full catalog is always dispatchable). This is enforced by
`selectTools` filtering the prompt list only, while `agent.go`/`web.go` build the dispatch map from the
full `tools()`.

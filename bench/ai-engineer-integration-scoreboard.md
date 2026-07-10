# AI Security Engineer — integration coverage (credential-free)

_Every integration exercised against a synthetic estate with PLANTED must-detect issues + hardened DECOYS, through the SAME snapshot-driven detectors the product runs — no mocks, no LLM, no external credential. Detection recall + FP-control per integration (§10: a hardened decoy yields nothing, so a flagged decoy is a real false positive)._

- **7/7 integrations clean-sweep** · overall recall **100%** (13/13 planted) · FP-control CLEAN (0 decoys flagged)

| Integration | Recall | Detected | Findings | Decoys flagged |
|---|---|---|---|---|
| OSINT external exposure | 100% | 3/3 | 3 | 0 ✓ |
| SaaS posture (SSPM · GitHub) | 100% | 1/1 | 4 | 0 ✓ |
| cloud attack-path (AI substrate) | 100% | 3/3 | 3 | 0 ✓ |
| cloud drift (change-control) | 100% | 1/1 | 1 | 0 ✓ |
| device posture (MDM) | 100% | 1/1 | 7 | 0 ✓ |
| identity (ITDR) | 100% | 2/2 | 3 | 0 ✓ |
| vendor risk (TPRM) | 100% | 2/2 | 3 | 0 ✓ |

## AI agent layer — recorded frontier run (Claude via dev proxy)

_Run credential-free via `tsbench integration --agent`, brain = frontier Claude through the file-relay
dev proxy (`LLM_BASE_URL=…:8898/v1`). Recall of the real issues + grounding (§10: a fabricated path or a
false-confirmed safe finding is invented). Recorded because it needs the manual proxy; the deterministic
table above regenerates anytime._

| Agent | Recall | Confirmed | Invented | Tool calls |
|---|---|---|---|---|
| AI Cloud Engineer (cloudagent) | 100% | 3/3 | 0 ✓ | 9 |
| AI Code Engineer (codeagent) | 100% | 1/1 | 0 ✓ | 6 |

- **Cloud**: confirmed all 3 internet→crown-jewel paths (2× internet→PII, 1× internet→admin privesc); rejected two ungrounded path attempts before grounding the admin chain via `find_paths` — the §10 guard working live.
- **Code**: confirmed the real string-concat SQLi and **refused** the parameterized-query decoy — no hallucinated exploit.

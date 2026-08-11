# Is a security-specialized model better on the analysis lane? — measured

The localization benchmark measures the CODE lane, where a general model won. That was unsurprising:
it is code navigation, and the defensive-security model vendors say plainly their models are not for
coding. So it left the interesting question open.

This measures the ANALYSIS lane on the security model's **own home turf**, with both arms matched at
8B and Q4_K_M so the comparison isolates specialization rather than size.

**The hypothesis is not supported.** The specialized model did not beat a general model of the same
size at security knowledge — and on the axis that matters most for a compliance product, it was
decisively worse.

## The task

Given raw scanner output carrying **no CWE**, name the weakness class.

This is security *knowledge*, not code reasoning, and it is close to CTI-RCM — one of the two
benchmarks Foundation-Sec publishes wins on. If specialization pays off anywhere in this product, it
should pay off here.

It is also a **real product gap**. §8's `compliance.map` hook keys on CWE (`Compliance.Lookup(cwes)`),
so a finding that arrives without one gets no specific control mapping. Plenty of real scanner output
is exactly that shape. Truth values are all keys in the shipped crosswalk
(`internal/tracer/hooks/data/compliance.json`), so a correct answer provably produces a real control
mapping rather than a plausible-sounding one (§10).

Two metrics, because in this product they are not equally important:

- **accuracy** — exact CWE match over the 14 in-crosswalk cases.
- **restraint** — share of the 6 out-of-crosswalk cases correctly *declined*. These are real findings
  real tools emit that are not weakness classes: a licence conflict, a complexity threshold, a cloud
  cost finding, a coverage gate, a refund-policy discrepancy, a flaky health probe.

## Result

| Engine | accuracy | restraint | over-attributed |
|---|---|---|---|
| keyword-substrate | 0.00 | 1.00 | 0/6 |
| `qwen3:8b` (general) | 0.57 | 0.67 | 2/6 |
| `foundation-sec-8b` (security) | 0.64 | **0.00** | **6/6** |

### Accuracy is a tie

0.57 vs 0.64 is one case in fourteen, and the direction **flipped between runs** — Foundation-Sec
scored 7 correct on the first run and 9 on the second over the *same* 14 cases, while qwen3 scored 8
both times. A one-case gap is well inside that variance. Neither model is measurably better at naming
the class.

Both do add genuine knowledge: the substrate scores 0.00 because the corpus describes symptoms and
never names the class, so ~+0.6 is a real lift over what any keyword layer can do.

### Restraint is where they separate, and it is not close

Foundation-Sec assigned a confident CWE to **every one of the six non-vulnerabilities** — including a
copyleft licensing conflict, a cyclomatic-complexity threshold, an under-utilised instance flagged for
cost, and a unit-test coverage gate. It held across both runs (0/2, then 0/6), so it is a property of
the model, not a sampling artifact.

For this product that is worse than being occasionally wrong. Compliance mapping is **annotation an
auditor reads** (§8). A fabricated CWE flows straight into control mappings that do not apply, and
lands in a signed evidence pack. The failure is silent: nothing downstream can tell an invented
attribution from a real one.

## What this means for the architecture

**Neither model can be trusted to decide "is this a weakness."** qwen3 is better at restraint but
still over-attributed 2 of 6 — so the finding is not "use the general model here", it is that the
judgement itself must not be delegated to a model.

That is a direct argument for the existing §10 discipline — *agent proposes, framework disposes* — and
against wiring an LLM into compliance mapping without a grounding gate. A usable design constrains the
model to the crosswalk's own key set and treats anything outside it as a decline, rather than trusting
the model to abstain on its own.

## Limits

1. **N=14 accuracy / N=6 restraint**, single trial per arm. The accuracy tie is credible because the
   gap is smaller than the observed run-to-run variance; the restraint gap is credible because it is
   total (6/6) and reproduced. Neither magnitude should be quoted precisely.
2. **Exact-match scoring is strict.** A defensible near-miss (CWE-79 for a cookie-flag issue) scores
   zero. Deliberate — the CWE must be right to yield the right controls — but it depresses both arms.
3. **One unparseable response** from Foundation-Sec, counted separately so a format weakness is never
   scored as a knowledge weakness. This reproduces the same intermittent formatting gap seen in the
   localization benchmark.
4. **This is Foundation-Sec-8B-Instruct specifically**, not a verdict on security-specialized models
   as a category.

## Reproducing

```bash
LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=qwen3:8b \
  go run ./cmd/tsbench cwemap --agent
```

The substrate baseline matches only **canonical CWE vocabulary** — the terms MITRE uses to name each
class. That constraint is what makes it honest: the corpus and the matcher have the same author, and a
table tuned to the corpus's own sentences scored 1.00 on the first attempt and proved nothing. Keying
only on the standard class name is what a real deterministic mapper would have without foreknowledge
of any particular finding.

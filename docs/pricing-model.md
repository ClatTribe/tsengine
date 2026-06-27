# Pricing model — the economics behind the three tiers (INR)

This is the cost calculation the pricing page is derived from. It exists so the tiers make
**economic sense** (each price covers its marginal cost with a healthy margin) and so the
"Free is genuinely free for us" claim is grounded, not marketing. The tiers are enforced by
`pkg/platform/plan.go` (`Entitlements`), so the page and the product can't drift.

## The cost drivers (per tenant, per month)

| Driver | What it is | Free | Growth |
|---|---|---|---|
| **LLM (L2 agent)** | The AI security+compliance engineer — investigations, AI fixes, ModeDeep. The dominant marginal cost. | **₹0** (AI off) | ~₹1,000 |
| Sandbox compute | The deterministic OSS scanners (all 5 categories) running in a per-scan container. | ~₹40 (2 assets, on-demand) | ~₹500 (≤25 assets, continuous) |
| Infra (amortized) | EC2 + store slice shared across tenants. | ~₹250 | ~₹350 |
| Threat-intel corpus | KEV/EPSS/ExploitDB/NVD — global, shared once, free feeds. | ₹0 | ₹0 |
| Storage / egress | findings, evidence, replay artifacts. | ~₹50 | ~₹150 |
| **Total cost to us** | | **≈ ₹340/mo** | **≈ ₹2,000/mo** |

The **load-bearing decision**: the LLM is the only large per-tenant cost, and it's the thing
the Free tier turns OFF (`AIEnabled:false` → `resolveAgentLLM` returns nil → no operator LLM
spend). What's left on Free is a shared-infra slice plus a couple of capped, on-demand
deterministic scans — a few hundred rupees that rounds to "free, forever" against the value of
a self-serve top-of-funnel. (A Free tenant who brings their OWN LLM key may still use AI — that
cost isn't ours; §18.5.)

## Deriving the Growth price

- Cost to serve: **≈ ₹2,000/mo**.
- Target gross margin: ~75% (standard B2B SaaS).
- Price = cost / (1 − margin) ≈ ₹2,000 / 0.25 = **₹8,000/mo** → set at **₹7,999/mo**.
- Annual: **₹79,990/yr** (≈ ₹6,666/mo — ~2 months free). Margin at annual ≈ 70%.

Positioning: well under the Indian compliance-SaaS incumbents (Sprinto/Vanta-class land at
₹3–8 lakh/yr) while covering all five categories *and* the AI engineer — accessible to the
SMB/startup ICP, still ~70–75% gross margin. Prices are exclusive of 18% GST.

## The three tiers (must match `Entitlements`)

| | Free | Growth (₹7,999/mo) | Enterprise (talk to us) |
|---|---|---|---|
| Scan targets (`MaxAssets`) | 2 | 25 | Unlimited |
| AI engineer (`AIEnabled`) | — | ✓ | ✓ |
| Continuous monitoring | — | ✓ | ✓ |
| Frameworks (`AllFrameworks`) | Core (SOC 2 readiness) | All 22 | All 22 + custom |
| HITL apply loop | — | ✓ | ✓ |
| Autonomous pentest | — | — | ✓ |

The five categories (code · cloud · attack surface · identity · compliance) are visible on
**every** tier — Free shows the real posture via the deterministic scanners; the paid tiers add
the AI engineer, continuous monitoring, evidence, and the apply loop on top.

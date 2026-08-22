# ADR 0022 — The signed-in product has one audience and one viewport; it needs two of each

**Status:** Proposed
**Date:** 2026-08-22

## Context

A designer's-eye audit of the signed-in product (34 routes, measured in-browser against a
seeded tenant) found four small defects, since fixed, and two that could not be fixed
without a decision. Both of those trace to the same unexamined assumption:

> **The app was built for a security operator sitting at a desk. It is sold to a founder
> who is neither.**

That assumption is invisible while you develop at 1440px on the machine that runs the
binary. It is not invisible to the customer.

### What was measured

**Viewport.** At 375px the shell does not adapt. The sidebar stays fixed at 224px, leaving
**151px** for all application content. There is no hamburger, no collapse, no breakpoint.
The Inbox — the human-in-the-loop approval queue, which `frontend/DESIGN.md` §2 names a
*signature surface* — renders at three words per line and cannot be operated.

The marketing site is fully responsive. The product is not. A visitor gets a better
experience before they pay than after.

This matters because of what the product promises. The pitch is that the agent works
continuously and *"pulls you in only where judgment is needed"*. The moment of judgment
arrives as a Slack alert saying **"3 fixes ready for your approval"**. The recipient is a
founder or a VP Eng, and the whole premise of the product is that they are not sitting in
a security console waiting. They are somewhere else, on a phone. That is not an edge case;
it is the designed-for path, and it is the one path that does not work.

**Audience.** `internal/platformapi/systemstate.go` emits a degradation banner reading:

> Exploitation intelligence (CISA KEV, EPSS) is 113 days old… **set
> `TSENGINE_THREAT_INTEL_CORPUS` and run `tsengine corpus refresh`** to keep it current.

The threat-intel corpus is **global world-state** (CLAUDE.md §7: *"This corpus is GLOBAL,
not per-tenant"*). A tenant cannot set an environment variable or run the binary — they do
not have one. `DegradationBar` renders in the `(app)` layout with **no role gate**, so
every signed-in user of every tenant is handed an instruction only the operator can carry
out, on the first screen after login, in an alarm-coloured band.

The honesty is not the problem and must not be weakened. The degradation layer exists
because three defects shipped where the backend knew something was wrong and the screen
did not say so. The problem is that one message is doing two jobs for two people, and the
person it reaches cannot act on it.

**A third finding is larger than it first looked.** Six of 44 text elements on Overview
fail WCAG AA. The worst were sidebar group labels at 10px in `--c-faint`, measured 2.82:1
against a required 4.5:1 (fixed). The remaining five share the same token — and so, it
turns out, does most of the app: **`text-faint` appears 489 times, 321 of them combined
with small text** (`text-xs`, `text-[10px]`, `text-[11px]`), which is exactly the failing
combination.

That number changes what the finding is. `--c-faint` (`#8B95A6`, roughly 3:1 on white) was
specified as a decorative value, but with 321 text call sites it is a text token in
practice, whatever the intent was. Treating this as hygiene and writing a rule against
future use would leave 321 existing failures in place while feeling addressed.

## Decision

### 1. Viewport tiers, not a responsive rewrite

Making 34 data-dense pages fully responsive is a quarter of work, and most of it would be
spent on surfaces nobody opens on a phone. Per CLAUDE.md §0 — rank by what it is worth to
the customer, done to the standard they will trust — we tier by whether the surface is
reached *because something happened*.

| Tier | Surfaces | Requirement |
|---|---|---|
| **1 — Operable on a phone** | Inbox (approve / reject / sign), Overview, Issues list + detail, Incidents | Full touch-grade layout. Every action completable. Targets ≥44px. This is the alert-response path. |
| **2 — Readable on a phone** | Compliance posture, Readiness, Assets, Engagements list, Activity | Legible and navigable; authoring actions may defer to desktop. Answers "what is the state" away from a desk. |
| **3 — Desktop-only, stated honestly** | Settings, Eval, Compliance scope + questionnaire, Program, Audits, Risks, Reports, the agent Consoles, operator console | A designed message naming the surface and why, not a crushed layout. |

Tier 3 is a real design deliverable, not a cop-out. A page that says *"Compliance scope is
built for a wide screen — open it on a laptop"* respects the reader. A page that renders
its controls into 151px does not, and it is the same failure mode as a silent degradation:
the product knows it cannot serve you and shows you a broken thing instead of saying so.

The shell gains a mobile pattern (collapsible sidebar behind a trigger, persistent tenant
context) so tiers 1 and 2 have somewhere to live.

### 2. System messages carry an audience

`Degradation` gains an `Audience` field — `tenant`, `operator`, or `both` — and
`DegradationBar` filters by the viewer's role. The same underlying condition may emit
different text to each:

| Reader | Gets | Because |
|---|---|---|
| Tenant | The **consequence**: "Some exploitation data is 113 days old, so severities may understate threats discovered since then." | They need to know the view may not mean what it says. |
| Operator | The **consequence and the remedy**: the above, plus the env var and the refresh command. | They are the only person who can act. |

Existing degradations are audited and assigned. The default for a new kind is **`both`**,
which is the safe direction: a message that reaches one person too many is noise, while a
message that reaches nobody recreates the silent-signal bug the layer was built to end.

### 3. Darken `--c-faint` rather than migrate 321 call sites

Three ways to close the contrast gap:

| Option | Cost | Trade-off |
|---|---|---|
| Migrate every text use to `--c-muted` | 321 call sites | Preserves the token's decorative intent; a project in its own right, and every missed site stays broken. |
| Add an AA-safe `--c-subtle` and migrate over time | 321 sites, spread | Two tokens that mean nearly the same thing, and a long window where the app is half-migrated. |
| **Darken `--c-faint` to meet 4.5:1 at 12px** | **one value** | Every call site is fixed at once. Faint text gets heavier, so the visual hierarchy flattens slightly. |

We take the third. The token is used for text 321 times; that is what it is, and its value
should meet the bar for what it is actually doing. The hierarchy loss is real but small —
the gap between `--c-muted` and `--c-faint` narrows rather than closes — and it is the
only option that does not leave known failures on screen while we work through a list.

**Both themes fail, and the values are computed, not estimated.** Contrast is measured
against the *page background*, not the card surface: `#F6F7F9` is the harder of the two
and a value tuned to white alone still fails there (`#707785` scores 4.50 on white and
4.20 on bg). Hue is preserved by scaling each existing value along its own channel ratio,
so the greys stay the same greys.

| Token | Now | Measured now | Proposed | Measured after |
|---|---|---|---|---|
| `--c-faint` (light) | `#8B95A6` | 3.02 white / **2.82 bg** | `#6A717E` → `106 113 126` | 4.91 white / **4.58 bg** |
| `--c-faint` (dark) | `#6E788C` | 4.35 bg / **4.03 surface** | `#768096` → `118 128 150` | 4.87 bg / **4.52 surface** |

The dark theme was failing too, which the audit did not catch because it was run in light
mode. Separation from `--c-muted` survives in both (light: 4.58 vs 5.59; dark: 4.52 vs
7.12), so faint still reads as the quieter of the two.

Caption text keeps a 12px floor regardless: no token value rescues 10px.

## Invariants

| Invariant | Mechanism |
|---|---|
| **Every action in the alert-response path is completable on a phone.** | Tier-1 routes carry a viewport test at 375px asserting no horizontal overflow, a reachable primary action, and ≥44px targets. |
| **A surface that cannot serve a viewport says so.** | Tier-3 routes render a designed narrow-viewport state. A crushed layout is a bug, not a fallback. |
| **No system message instructs a reader to do something they cannot do.** | `Degradation.Audience` is required; the existing guard test that drives every declared kind is extended to assert each has an audience and that no `tenant`-visible detail contains an env var, a shell command, or a host-level instruction. |
| **A new degradation kind reaches someone.** | Default `both`. Omitting the field is a compile error, not a silent narrowing. |
| **Every text token meets AA at its smallest permitted size.** | A test samples rendered text across the tier-1 and tier-2 routes, composites alpha against the real background stack, and asserts ≥4.5:1 (≥3:1 for large text) and ≥12px. Measuring the rendered result rather than the token catches the combination, which is where the failure actually lives. |

## Consequences

**We are choosing not to build a mobile app.** Tiers 1 and 2 are responsive web on the
existing shell. A native app is a separate product with its own release surface, and
nothing in the review argues for one.

**We are choosing not to make everything responsive.** Tier 3 is an explicit, permanent
category. Someone will eventually ask why Settings does not work on a phone; the answer is
written down here, and the page itself says it.

**The banner will get quieter for tenants and louder for operators.** That is the point.
The operator-facing half currently has no home — there is an operator console
(`/operator`, ADR §18.5) and these messages belong in it.

**Cost.** Tier 1 is the real work: four surfaces, touch-grade. Tier 2 is mostly container
widths and table-to-card fallbacks. Tier 3 is one shared component and a route list. The
audience split is a field, a filter, and a copy pass over the existing degradation kinds.
The contrast fix is one token value plus a visual check that the flatter hierarchy still
reads — deliberately the cheapest of the three, because the alternative that preserved the
design intent cost 321 edits and would have left failures standing while it ran.

**What this does not address.** The review found the Inbox to be the strongest screen in
either surface — evidence, citing finding, and the irreversible-action gate stated plainly
(*"Nothing is sent until a person signs"*). None of that changes. This ADR is about who is
holding the screen and how wide it is, not about what the screen says.

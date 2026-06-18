# Sentinel — the agentic security console

> The world-class, dark **command-center** UX for the fractional autonomous security team.
> A separate Next.js app (App Router / RSC) that consumes the Go `/v1` JSON API. The Go
> `internal/console` (zero-JS) stays as the lightweight fallback; this is the flagship UX.

---

## 1. Product thesis → UX thesis

The product is **a security team that runs itself, and pulls you in only where judgment is
needed.** So the UX is not a dashboard you *operate* — it's a **command center you
supervise.** Three feelings to engineer:

1. **"Am I safe?"** answered in one glance (the founder).
2. **"What is the agent doing right now?"** — its work is *visible*, a live feed, never a
   black box (trust).
3. **"This needs you."** — the human-in-the-loop is a *delightful*, keyboard-fast inbox,
   not a buried form (the operator).

Aesthetic north stars: **Linear** (density, keyboard, motion), **Vercel** (calm dark
surfaces, type), **Watchtower/Datadog** (live telemetry without anxiety). Dark, technical,
fast. Monospace for machine data; a single confident accent for "the agent".

---

## 2. Information architecture

```
┌── Top bar: tenant switcher · global ⌘K · "agent live" pulse · risk pill · account
│
├── Sidebar (icon+label, collapsible)
│    ◆ Overview        — Mission Control: am I safe + what the agent did
│    ◆ Inbox           — the HITL approval queue (badge = pending count)   ★ signature
│    ◆ Findings        — detected issues, filter + drill-down to evidence
│    ◆ Incidents       — continuous-monitoring timeline (new / resolved)
│    ◆ Compliance      — posture per framework → control drill-down → report
│    ◆ Assets          — what's monitored + connect a system + scan now
│    ─────────
│    ◆ Activity        — the raw agent log (everything it did, signed)
│
└── ⌘K command palette: jump anywhere + run actions (approve, scan, connect, export)
```

The two **signature surfaces** (what makes it feel agentic, not just a SaaS dashboard):

- **Inbox** — every tier-2+ action the agent proposes lands here as a card: *what it wants
  to do, why (the citing finding), the blast radius, Approve / Reject / Edit*. Keyboard:
  `j/k` move, `a` approve, `r` reject, `e` edit, `⏎` open. Feels like Superhuman for
  security decisions.
- **Activity / live feed** — a persistent stream (on Overview + its own page) of agent
  events: *scanned acme/web · found 3 criticals · opened incident · proposed fix · awaiting
  you*. Near-real-time. This is the "the team is working" heartbeat.

---

## 3. The design system ("command-center")

| Token | Value (dark) | Use |
|---|---|---|
| `bg` | `#0A0B0F` | app background (near-black, slight blue) |
| `surface` | `#111318` | cards |
| `surface-2` | `#161922` | raised / hover |
| `border` | `#222632` | hairlines |
| `text` | `#E6E9EF` / `muted #8B94A7` | copy |
| `accent` | `#5B8CFF` (electric blue) | "the agent", primary actions, focus |
| `agent-pulse` | `#36E2A4` (mint) | live/working indicator, "fixed", success |
| severity | critical `#FF4D4F` · high `#FF7A45` · medium `#FAAD14` · low `#52C41A` | |

- **Type**: Geist Sans (UI) + Geist Mono / JetBrains Mono (IDs, scopes, code, telemetry).
- **Motion**: 120–200ms ease-out; content fades+rises 4px on mount; the "agent" pulse is a
  soft 2s breathing dot. Respect `prefers-reduced-motion`.
- **Density**: compact by default (Linear-grade), generous on the founder Overview.
- Built with **Tailwind v3** + a small set of **hand-rolled shadcn-style primitives**
  (Button, Card, Badge, Dialog, CommandPalette, Sheet, Skeleton) — no heavy UI dep.

---

## 4. Architecture & data flow

```
Browser ──▶ Next.js (RSC + Route Handlers) ──server-side fetch──▶ Go /v1 API
                       │
              httpOnly cookies: ts_token (platform bearer) + ts_tenant
```

- **Auth**: login posts the platform token + tenant to a Next.js Route Handler, which sets
  **httpOnly + SameSite=Strict** cookies. Server Components/Actions read them and call the
  Go API **server-side** (`Authorization: Bearer …` + `X-Tenant-ID`). The browser never
  sees the token; no CORS. `TSENGINE_API_URL` points at the Go API.
- **Reads**: Server Components fetch (cacheless, per-request) for first paint. **Live
  updates** (Phase 8): a single `EventSource` (`<LiveStatus>`) subscribes to the same-origin
  SSE proxy (`/api/events` → Go `GET /v1/events`); when the server pushes a changed `state`
  snapshot it calls `router.refresh()`, re-rendering the current view — so the whole
  dashboard is live without per-component polling. **Writes** (approve/reject, scan, connect) go through **Server Actions**
  → the gated Go endpoints (`POST /v1/approvals/{id}`, `/v1/rescan`, …). The HITL gate,
  tiers, and signed ledger are unchanged — this UI is a client of the same gate.
- **Engine untouched** (CLAUDE.md §18.2 invariant 1). This is presentation only.

API consumed (all exist today): `GET /v1/findings · /v1/findings/export · /v1/incidents ·
/v1/approvals · /v1/connections · /v1/engagements · /v1/posture/{f} ·
/v1/compliance/{f}/report` · `POST /v1/approvals/{id} · /v1/rescan · /v1/tenants ·
/v1/connect/{kind}`.

---

## 5. Build phases (each ships independently; verified with `next build` + a frontend CI)

| Phase | Scope | Status |
|---|---|---|
| **0 — Foundation** | `frontend/` scaffold (Next 15 + TS + Tailwind), the design system, app shell (sidebar/topbar), API client + cookie auth, login, an **Overview** skeleton, frontend CI | ← this PR |
| **1 — Mission Control** | the real Overview: risk hero, severity, "needs you" CTA, live **activity feed**, posture strip, monitored-assets summary | |
| **2 — Inbox (HITL)** | the approval queue as a keyboard-driven triage inbox; Approve/Reject/Edit via Server Actions through the gated desk | |
| **3 — Findings** | filterable list + the evidence drill-down (CWE/MITRE/KEV/EPSS/controls); export menu (SARIF/CSV) | |
| **4 — Incidents** | the continuous-monitoring timeline (new / resolved), grouped by pass, with the agent's actions | |
| **5 — Compliance** | posture cards → per-control drill-down → signed report download | ✅ shipped |
| **6 — Assets & onboarding** | connect a system (OAuth handoff), monitored assets, scan-now, connection health | ✅ shipped |
| **7 — Command palette + polish** | ⌘K, global keyboard nav, motion pass, empty/loading/error states, responsive, a11y | ✅ shipped |
| **8 — Real-time (backend + FE)** | a Go SSE endpoint (`GET /v1/events`) → the feed/inbox update live instead of polling | ✅ shipped |

## 6. Project structure

```
frontend/
  app/
    layout.tsx            globals.css        login/page.tsx
    api/session/route.ts  (auth cookie set/clear)
    (app)/                authed shell + the screens (overview, inbox, findings, …)
  components/  shell/ (sidebar, topbar) · ui/ (primitives) · feature components
  lib/         api.ts (server client) · auth.ts (cookies) · types.ts · utils.ts
  DESIGN.md (this) · README.md · .env.example
```

The Go API is the backend; `frontend/` is the decoupled presentation layer. CLAUDE.md §18
gets a pointer. Deploy: `next build` → standalone (its own service) — or later `go:embed`
the static export for the single-binary story.

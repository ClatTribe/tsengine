# TensorShield — agentic security console

The world-class dark **command-center** UX for the autonomous security team. A Next.js
(App Router / RSC) app that consumes the Go `/v1` JSON API. See **[DESIGN.md](DESIGN.md)**
for the IA, design system, and build phases.

## Dev
```sh
cp .env.example .env.local            # point TSENGINE_API_URL at the Go API
npm install
npm run dev                           # http://localhost:3000  → sign in with the platform token
```
The Go API: `TSENGINE_PLATFORM_TOKEN=dev TSENGINE_PLATFORM_NO_ENGINE=1 go run ./cmd/platform` (port :8090).

## How auth works
Login posts the platform bearer token + tenant id to a Next.js Route Handler, which sets
httpOnly cookies. Server Components/Actions call the Go API **server-side** with those —
the browser never sees the token, and there is no CORS.

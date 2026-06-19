# tsengine frontend image — the Next.js command-center UX (frontend/, CLAUDE.md §18).
#
# A standalone production server (next.config.mjs `output: "standalone"`) on :3000. It
# renders Server Components that fetch the Go platform API server-side, so it needs
# TSENGINE_API_URL pointing at the platform (e.g. http://platform:8090 in compose). The
# session token lives in an httpOnly cookie — never exposed to the browser.
#
# Build (context = this frontend/ directory):
#   docker build -t tsengine/frontend:dev frontend/

# ---- deps ----
FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# ---- build ----
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ---- runtime ----
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000
# The standalone bundle: a self-contained server.js + the minimal node_modules it needs,
# plus the static assets (which standalone does not copy itself).
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
EXPOSE 3000
USER node
CMD ["node", "server.js"]

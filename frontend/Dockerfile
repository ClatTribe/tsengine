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
RUN npm install --no-audit --no-fund

# ---- build ----
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# NEXT_PUBLIC_* values are INLINED INTO THE BUNDLE AT BUILD TIME — passing them only as
# runtime container env has no effect. They must arrive here as build args or the published
# pages silently keep their source defaults: canonical/sitemap URLs point at the placeholder
# domain, and the legal documents render without a named entity or jurisdiction.
ARG NEXT_PUBLIC_SITE_URL
ARG NEXT_PUBLIC_LEGAL_ENTITY
ARG NEXT_PUBLIC_LEGAL_JURISDICTION_CITY
ARG NEXT_PUBLIC_LEGAL_COUNTRY
ARG NEXT_PUBLIC_LEGAL_ADDRESS
ARG NEXT_PUBLIC_SMTP_SUBPROCESSOR
ARG NEXT_PUBLIC_CONTACT_EMAIL
ARG NEXT_PUBLIC_CONTACT_PHONE
ARG NEXT_PUBLIC_CONTACT_PHONE_TEL
ARG NEXT_PUBLIC_PRIVACY_EMAIL
ARG NEXT_PUBLIC_SECURITY_EMAIL
ARG NEXT_PUBLIC_LEGAL_EMAIL
ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_SITE_URL=${NEXT_PUBLIC_SITE_URL} \
    NEXT_PUBLIC_LEGAL_ENTITY=${NEXT_PUBLIC_LEGAL_ENTITY} \
    NEXT_PUBLIC_LEGAL_JURISDICTION_CITY=${NEXT_PUBLIC_LEGAL_JURISDICTION_CITY} \
    NEXT_PUBLIC_LEGAL_COUNTRY=${NEXT_PUBLIC_LEGAL_COUNTRY} \
    NEXT_PUBLIC_LEGAL_ADDRESS=${NEXT_PUBLIC_LEGAL_ADDRESS} \
    NEXT_PUBLIC_SMTP_SUBPROCESSOR=${NEXT_PUBLIC_SMTP_SUBPROCESSOR} \
    NEXT_PUBLIC_CONTACT_EMAIL=${NEXT_PUBLIC_CONTACT_EMAIL} \
    NEXT_PUBLIC_CONTACT_PHONE=${NEXT_PUBLIC_CONTACT_PHONE} \
    NEXT_PUBLIC_CONTACT_PHONE_TEL=${NEXT_PUBLIC_CONTACT_PHONE_TEL} \
    NEXT_PUBLIC_PRIVACY_EMAIL=${NEXT_PUBLIC_PRIVACY_EMAIL} \
    NEXT_PUBLIC_SECURITY_EMAIL=${NEXT_PUBLIC_SECURITY_EMAIL} \
    NEXT_PUBLIC_LEGAL_EMAIL=${NEXT_PUBLIC_LEGAL_EMAIL}
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

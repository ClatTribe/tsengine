# tsengine platform image — the multi-tenant SaaS server (`cmd/platform`, CLAUDE.md §18).
#
# Serves the /v1 JSON API + the /ui console on :8090. By default it runs WITHOUT the
# sandbox engine (TSENGINE_PLATFORM_NO_ENGINE=1) — identity/workspace ("operate") assets
# and the whole loop (auth, dashboard, approvals, compliance) work; tech-asset scanning
# needs the sandbox. To enable the engine, build the sandbox image (`make sandbox-image`),
# mount the Docker socket into this container, and unset NO_ENGINE — the platform shells
# out to `docker run` to spawn per-scan sandbox containers (CLAUDE.md §12), so the docker
# CLI is bundled here.
#
# Build (from repo root):
#   docker build -t tsengine/platform:dev -f docker/platform/Dockerfile --build-arg VERSION=$(git describe --tags --always) .

# ---- build ----
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY pkg ./pkg
COPY internal ./internal
COPY cmd ./cmd
# CGO off → static binary (password hashing is stdlib crypto/pbkdf2; no cgo needed).
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o /out/platform ./cmd/platform

# ---- runtime ----
FROM debian:bookworm-slim
# ca-certificates: outbound HTTPS (OAuth, connectors). curl: healthcheck.
# docker.io: only used when the sandbox engine is enabled (socket mounted).
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/platform /usr/local/bin/platform

# No TSENGINE_PLATFORM_ADDR default here: the binary binds $PORT when a PaaS (Render/Railway/Fly)
# injects it, else :8090 — pinning ADDR would override $PORT and break PaaS port routing.
ENV TSENGINE_PLATFORM_DB=/data/platform.json
EXPOSE 8090
VOLUME ["/data"]

# /healthz needs no auth.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:8090/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/platform"]

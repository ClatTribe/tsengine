# tsengine host service image — the long-running engine (`tsengine serve`).
#
# The host orchestrates by shelling out to `docker run` to spawn per-scan sandbox
# containers (CLAUDE.md §12), so this image bundles the docker CLI and MUST run with
# access to a Docker daemon — mount the socket (`-v /var/run/docker.sock:...`) or
# point DOCKER_HOST at a remote/rootless daemon. See docs/DEPLOYMENT.md.
#
# Build (from repo root):
#   docker build -t tsengine/host:dev -f docker/host/Dockerfile --build-arg VERSION=$(git describe --tags --always) .
# Run:
#   docker run -p 8080:8080 \
#     -e TSENGINE_API_TOKEN=$(openssl rand -hex 24) \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     -v "$PWD/runs:/data/runs" \
#     tsengine/host:dev

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
# CGO off → static binary; the host needs no cgo (it shells out to docker).
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o /out/tsengine ./cmd/tsengine

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/tsengine /usr/local/bin/tsengine

ENV TSENGINE_ADDR=:8080 \
    TSENGINE_RUNS_DIR=/data/runs
EXPOSE 8080
VOLUME ["/data/runs"]

# Liveness from the orchestrator's perspective; /healthz needs no auth.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:8080/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/tsengine"]
CMD ["serve"]

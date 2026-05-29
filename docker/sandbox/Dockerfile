# tsengine sandbox image — see CLAUDE.md §12 for the host/sandbox model.
#
# Stage 1: build the tool-server binary statically against the project source.
# Stage 2: ubuntu base, bake nuclei + templates, drop the tool-server in.
#
# Build (from repo root):
#   docker build -t tsengine/sandbox:0.1.0 -f docker/sandbox/Dockerfile .

# ---- Stage 1: tool-server build ----
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder

ARG TARGETOS=linux
ARG TARGETARCH=arm64

WORKDIR /src
COPY go.mod go.sum ./
COPY pkg ./pkg
COPY internal ./internal
COPY cmd ./cmd

ENV CGO_ENABLED=0 GO111MODULE=on

# Build the tool-server.
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -X main.Version=sandbox-0.1.0" \
    -o /out/tool-server ./cmd/tool-server

# Build dalfox from source — naming on dalfox releases has been
# historically inconsistent; `go install` is deterministic.
ARG DALFOX_VERSION=latest
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go install github.com/hahwul/dalfox/v2@${DALFOX_VERSION}

# subfinder — ProjectDiscovery, Go.
ARG SUBFINDER_VERSION=latest
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}

# gitleaks — secret scanner (repository asset), Go. NOTE the module path
# is still declared as zricethezav/gitleaks even though the repo moved
# orgs, so install by that path.
ARG GITLEAKS_VERSION=latest
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go install github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}

# Additional Go-native scanners (CGO-free): grype (SCA, anchore), httpx
# (ProjectDiscovery HTTP prober), dockle (container CIS linter).
# trufflehog is NOT here — its go.mod has replace directives that block
# `go install`; it's installed via its release script in stage 2.
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go install github.com/anchore/grype/cmd/grype@latest \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go install github.com/goodwithtech/dockle/cmd/dockle@latest \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go install github.com/projectdiscovery/katana/cmd/katana@latest

# ---- Stage 2: runtime image ----
FROM ubuntu:22.04

ARG TARGETARCH=arm64
ARG NUCLEI_VERSION=3.3.7

# Minimal runtime deps. ca-certificates needed for nuclei to update
# templates / fetch HTTPS targets. nmap is the ip Handler's anchor;
# trivy is the container Handler's anchor (installed via official apt
# repo for reliable, signed builds).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip gnupg lsb-release nmap \
    && curl -fL https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
        > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends trivy python3 python3-pip python3-venv git \
    && rm -rf /var/lib/apt/lists/*

# semgrep (repository SAST — the OWASP Benchmark tool), prowler
# (cloud_account posture), sqlmap (web SQLi specialist). All Python;
# installed system-wide so the non-root runtime user can invoke them.
RUN pip3 install --no-cache-dir --break-system-packages \
        semgrep==1.96.0 prowler==4.6.0 sqlmap \
    || pip3 install --no-cache-dir semgrep prowler sqlmap

# Install nuclei. Use the linux/<arch> release matching the host arch.
RUN curl -fL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
    && unzip -d /tmp /tmp/nuclei.zip \
    && mv /tmp/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/LICENSE.md /tmp/README.md

# Drop in the tool-server + Go-built scanner binaries built in stage 1.
COPY --from=builder /out/tool-server /usr/local/bin/tool-server
COPY --from=builder /go/bin/dalfox /usr/local/bin/dalfox
COPY --from=builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /go/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /go/bin/grype /usr/local/bin/grype
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=builder /go/bin/dockle /usr/local/bin/dockle
COPY --from=builder /go/bin/katana /usr/local/bin/katana

# trufflehog via its official release script (go install is blocked by
# replace directives in its go.mod). Pins to /usr/local/bin.
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# Non-root runtime user. Tool-server doesn't need root; we keep it
# isolated even inside the sandbox.
RUN useradd --create-home --uid 1000 tsengine
USER tsengine

# Pre-fetch the nuclei templates AS the runtime user. v3 installs them
# to $HOME/nuclei-templates/ (not $HOME/.local/share/). The image digest
# pins this corpus version — CLAUDE.md §10.
RUN /usr/local/bin/nuclei -update-templates -silent \
    && test -d /home/tsengine/nuclei-templates/ \
    && find /home/tsengine/nuclei-templates/ -name '*.yaml' | head -1 | grep -q .

# Pre-fetch semgrep's registry rulesets AS the runtime user so scans
# don't pay a network cost and stay pinned to this image. A throwaway
# scan populates ~/.semgrep with the security-audit + secrets packs.
RUN mkdir -p /tmp/semgrep-warm && printf 'x = 1\n' > /tmp/semgrep-warm/warm.py \
    && semgrep scan --config p/security-audit --config p/secrets \
        --quiet --disable-version-check --metrics off /tmp/semgrep-warm >/dev/null 2>&1 || true

ENV TSENGINE_ADDR=:8080
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/tool-server"]

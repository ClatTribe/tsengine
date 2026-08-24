# tsengine sandbox image — see CLAUDE.md §12 for the host/sandbox model.
#
# Stage 1: build the tool-server binary statically against the project source.
# Stage 2: ubuntu base, bake nuclei + templates, drop the tool-server in.
#
# Build (from repo root):
#   docker build -t tsengine/sandbox:0.1.0 -f docker/sandbox/Dockerfile .

# ---- Stage 1: tool-server build ----
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS builder

ARG TARGETOS=linux
ARG TARGETARCH=arm64

WORKDIR /src
COPY go.mod go.sum ./
COPY pkg ./pkg
COPY internal ./internal
COPY cmd ./cmd

# GOTOOLCHAIN=auto lets `go install <tool>@latest` download a newer Go
# toolchain when a tool's go.mod requires one (e.g. osv-scanner v2 needs
# go >= 1.26). The golang images default to GOTOOLCHAIN=local, which would
# hard-fail those installs. Only the builder stage is affected (discarded).
ENV CGO_ENABLED=0 GO111MODULE=on GOTOOLCHAIN=auto

# Build the tool-server.
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -X main.Version=sandbox-0.1.0" \
    -o /out/tool-server ./cmd/tool-server

# TOOLSET in the BUILDER stage. This is where the real cost is: each `go install` drags its own
# dependency tree, and the expensive ones are asset-specific — cloudfox pulls the whole AWS SDK
# (cloud), amass a large graph/DNS stack (domain), the ProjectDiscovery set (web/api/ip). Building
# all of them cost ~16GB of build cache before this gate existed, which is more than a 16GB laptop
# has spare.
#
# Tools NOT selected get a STUB at the same path instead of being skipped outright, because the
# runtime stage COPYs each binary unconditionally and Docker cannot make a COPY conditional. The stub
# exits non-zero with a clear message, so a partial image reports a tool as unavailable rather than
# silently behaving as though it ran — the same rule the product applies to its own findings.
ARG TOOLSET=full
ENV TS_TOOLSET=${TOOLSET}
COPY docker/sandbox/toolset.sh /usr/local/bin/ts_want.sh
RUN chmod +x /usr/local/bin/ts_want.sh

# Build dalfox from source — naming on dalfox releases has been
# historically inconsistent; `go install` is deterministic.
ARG DALFOX_VERSION=v2.13.0
RUN . /usr/local/bin/ts_want.sh && GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    ts_install web dalfox github.com/hahwul/dalfox/v2@${DALFOX_VERSION}

# subfinder — ProjectDiscovery, Go.
ARG SUBFINDER_VERSION=v2.16.0
RUN . /usr/local/bin/ts_want.sh && GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    ts_install domain subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}

# gitleaks — secret scanner (repository asset), Go. NOTE the module path
# is still declared as zricethezav/gitleaks even though the repo moved
# orgs, so install by that path.
ARG GITLEAKS_VERSION=v8.30.1
RUN . /usr/local/bin/ts_want.sh && GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    ts_install "repository mobile" gitleaks github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}

ARG NAABU_VERSION=v2.6.1
# Additional Go-native scanners (CGO-free): grype (SCA, anchore), httpx
# (ProjectDiscovery HTTP prober), dockle (container CIS linter).
# trufflehog is NOT here — its go.mod has replace directives that block
# `go install`; it's installed via its release script in stage 2.
RUN . /usr/local/bin/ts_want.sh && export GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    && ts_install "repository container" grype github.com/anchore/grype/cmd/grype@v0.117.0 \
    && ts_install "web api domain ip" httpx github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0 \
    && ts_install container dockle github.com/goodwithtech/dockle/cmd/dockle@v0.4.14 \
    && ts_install web katana github.com/projectdiscovery/katana/cmd/katana@v1.7.0 \
    && ts_install repository gosec github.com/securego/gosec/v2/cmd/gosec@v2.28.0 \
    && ts_install repository govulncheck golang.org/x/vuln/cmd/govulncheck@v1.7.0

# naabu — fast port scanner, the ip_address recon tool (A1). Requires
# libpcap + CGO (unlike the other ProjectDiscovery tools). Our wrapper
# uses CONNECT scan (-s c) so no CAP_NET_RAW is needed at runtime, but the
# binary still links libpcap. Built natively for TARGETARCH (CGO cross-
# compile would need a cross toolchain; the supported build host matches
# the target arch).
RUN . /usr/local/bin/ts_want.sh \
    && if ts_want ip; then apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
       && CGO_ENABLED=1 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
          go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} || ts_stub naabu; \
       else echo "skip naabu (TOOLSET=$TS_TOOLSET)"; ts_stub naabu; fi \
    && rm -rf /var/lib/apt/lists/*

# amass — OWASP subdomain enumerator (domain asset, A2). Go, CGO-free.
RUN . /usr/local/bin/ts_want.sh && GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    ts_install domain amass github.com/owasp-amass/amass/v4/...@v4.2.0

# osv-scanner — Google OSV.dev SCA (repository asset, A5). Go, CGO-free.
RUN . /usr/local/bin/ts_want.sh && GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    ts_install repository osv-scanner github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.5.1

# cloudfox — BishopFox read-only cloud IAM attack-path enum (cloud_account
# registry tier, A3). Go, CGO-free.
RUN . /usr/local/bin/ts_want.sh && GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    ts_install cloud cloudfox github.com/BishopFox/cloudfox@v1.17.0

# ffuf — web content discovery (web escalation, E1). Go, CGO-free.
RUN . /usr/local/bin/ts_want.sh && GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    ts_install web ffuf github.com/ffuf/ffuf/v2@v2.2.1

# kiterunner — undocumented API route discovery (api escalation, E2). Go.
# The binary's main package is cmd/kiterunner (NOT cmd/kr); install it and
# rename to `kr` (the name the wrapper invokes). Pinned to v1.0.2 — `@latest`
# resolved to a tree WITHOUT cmd/kr and broke the build (it only succeeded
# before via a stale build-cache layer).
RUN . /usr/local/bin/ts_want.sh \
    && if ts_want api; then GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
         go install github.com/assetnote/kiterunner/cmd/kiterunner@v1.0.2 \
       && mv /go/bin/kiterunner /go/bin/kr || ts_stub kr; \
       else echo "skip kr (TOOLSET=$TS_TOOLSET)"; ts_stub kr; fi

# cosign — image signature / SLSA provenance verification (container, E4).
# Go, CGO-free.
RUN . /usr/local/bin/ts_want.sh && GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    ts_install container cosign github.com/sigstore/cosign/v2/cmd/cosign@v2.6.5

# ---- Stage 2: runtime image ----
FROM ubuntu:22.04

ARG TARGETARCH=arm64
ARG NUCLEI_VERSION=3.3.7

# TOOLSET selects which ASSETS' tooling to install. Default `full` is production parity — every asset,
# byte-identical to what shipped before this arg existed.
#
# WHY IT EXISTS: the image installs tooling for all seven assets whether or not you scan them, and the
# heavy half is asset-specific — CodeQL (~1GB) and KICS serve `repository` escalation only, prowler /
# scoutsuite / checkov serve `cloud_account` only, and
# the nuclei template corpus + SecLists serve the web/api/ip family. A developer working on container
# and repository scanning pays for all of it, on every rebuild, and a 16GB laptop runs out of disk
# before the build finishes. (It did.)
#
# Pass a comma-separated asset list to build only what you need:
#   docker build --build-arg TOOLSET=container,repository ...
# Recognised: container, repository, web, api, ip, domain, cloud, ai. Unknown names are ignored, so a
# typo yields a smaller image rather than a broken one — check the build log's TOOLSET line.
#
# This is a DEV convenience. Anything but `full` produces an image that cannot scan every asset, and
# the tool-server will report the missing tools as unavailable rather than pretend (§10). Never deploy
# a partial image expecting full coverage.
ARG TOOLSET=full
ENV TS_TOOLSET=${TOOLSET}
RUN echo "TOOLSET=${TOOLSET}" && mkdir -p /etc/tsengine && echo "${TOOLSET}" > /etc/tsengine/toolset

# Minimal runtime deps. ca-certificates needed for nuclei to update
# templates / fetch HTTPS targets. nmap is the ip Handler's anchor;
# trivy is the container Handler's anchor (installed via official apt
# repo for reliable, signed builds).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip gnupg lsb-release nmap libpcap0.8 hydra nikto \
    && curl -fL https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
        > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends trivy python3 python3-pip python3-venv git \
    && rm -rf /var/lib/apt/lists/*

COPY docker/sandbox/toolset.sh /usr/local/bin/ts_want.sh
RUN chmod +x /usr/local/bin/ts_want.sh

# semgrep (repository SAST — the OWASP Benchmark tool), prowler
# (cloud_account posture), sqlmap (web SQLi specialist). All Python;
# installed system-wide so the non-root runtime user can invoke them.
# Install each Python tool independently so one dependency conflict can't
# fail the whole image — a missing tool degrades gracefully at runtime. The
# heavy resolvers (semgrep/prowler/checkov/scoutsuite) often pin
# incompatible shared deps; isolating each install avoids backtracking hell.
#
# garak (the ai_application anchor) WAS installed here and is not any more. Nothing could dispatch it:
# no asset handler, no agent, no dispatcher, and no `ai_application` asset type to point at it — it
# was the only registered tool with zero callers. It shipped a large ML dependency set in every image
# for a capability that could not be invoked. It returns when the asset does (ADR 0012).
RUN . /usr/local/bin/ts_want.sh \
    && PKGS="" \
    && { ts_want_any "repository mobile" && PKGS="$PKGS semgrep==1.96.0 mobsfscan"; } || true \
    && { ts_want repository && PKGS="$PKGS bandit"; } || true \
    # apkid analyses a BUILT APK, which is the mobile_application capability §3 deprecated. mobsfscan
    # stays: it is the mobile-SOURCE escalation inside a connected repository, which is supported.
    && { ts_want mobile && PKGS="$PKGS apkid"; } || true \
    && { ts_want_any "web api" && PKGS="$PKGS sqlmap"; } || true \
    && { ts_want domain && PKGS="$PKGS checkdmarc dnstwist"; } || true \
    && { ts_want_any "api web" && PKGS="$PKGS schemathesis"; } || true \
    && { ts_want api && PKGS="$PKGS inql"; } || true \
    && { ts_want cloud && PKGS="$PKGS prowler==4.6.0 scoutsuite"; } || true \
    && { ts_want_any "repository cloud" && PKGS="$PKGS checkov"; } || true \
    && { ts_want repository && PKGS="$PKGS modelscan"; } || true \
    && echo "python toolset: ${PKGS:-<none>}" \
    # A CONSTRAINTS FILE, because the pin above was being silently defeated. These installs run ONE
    # AT A TIME on purpose (isolation, see the comment above), which means `semgrep==1.96.0` installs
    # first and then `mobsfscan` — which requires semgrep UNPINNED — quietly upgrades it. Measured:
    # the Dockerfile pinned 1.96.0 and the image ran 1.172.0, while `tool-freshness` reported 1.96.0.
    # A version claim about a binary that is not the one installed, which is the same defect as
    # claiming a version for a binary that is not there at all. A constraint applies across every
    # install without merging them into one resolve, so the isolation is kept and the pin holds.
    && printf 'semgrep==1.96.0\n' > /tmp/pip-constraints.txt \
    && for p in $PKGS; do \
        pip3 install --no-cache-dir --break-system-packages -c /tmp/pip-constraints.txt "$p" \
        || pip3 install --no-cache-dir -c /tmp/pip-constraints.txt "$p" \
        || echo "WARN: pip install $p failed (tool will be unavailable)"; \
    done \
    && rm -f /tmp/pip-constraints.txt

# wpscan (WordPress CMS-specialist DAST — web registry/escalation tool).
# Ruby gem; best-effort so a build-time failure degrades to "unavailable"
# at runtime rather than failing the whole image.
RUN . /usr/local/bin/ts_want.sh \
    && if ts_want web; then \
       apt-get update \
       && apt-get install -y --no-install-recommends ruby ruby-dev build-essential \
       && (gem install wpscan --no-document || echo "WARN: gem install wpscan failed (tool will be unavailable)") \
       && rm -rf /var/lib/apt/lists/* ; \
    else echo "skip wpscan (TOOLSET=$TS_TOOLSET)"; fi

# padbuster (CRYPTO specialist — AES-CBC/block-cipher padding-oracle decrypt+forge; the dispatch_oss
# crypto answer). A single Perl script (GDSSecurity original), needs perl + libwww-perl (LWP). Not in
# apt. Best-effort so a fetch failure degrades to "unavailable" at runtime rather than failing the image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends perl libwww-perl libcrypt-ssleay-perl \
    && (curl -fL -o /usr/local/bin/padbuster \
          https://raw.githubusercontent.com/GDSSecurity/PadBuster/master/padBuster.pl \
        && chmod +x /usr/local/bin/padbuster \
        || echo "WARN: padbuster install failed (tool will be unavailable)") \
    && rm -rf /var/lib/apt/lists/*

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
COPY --from=builder /go/bin/naabu /usr/local/bin/naabu
COPY --from=builder /go/bin/amass /usr/local/bin/amass
COPY --from=builder /go/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /go/bin/cloudfox /usr/local/bin/cloudfox
COPY --from=builder /go/bin/ffuf /usr/local/bin/ffuf
COPY --from=builder /go/bin/kr /usr/local/bin/kr
COPY --from=builder /go/bin/cosign /usr/local/bin/cosign
# gosec was `go install`ed in the builder but never copied here, so the wrapper's exec("gosec") could
# only ever fail — registered and dispatchable on both sides, yet unrunnable. govulncheck (repository
# escalation: the Go module/stdlib advisory check) was registered on both sides but its binary was
# missing from this image entirely. Registration parity is necessary but NOT sufficient: the binary has
# to be in the final stage too, which is what internal/toolsbundle's image-coverage test now asserts.
COPY --from=builder /go/bin/gosec /usr/local/bin/gosec
COPY --from=builder /go/bin/govulncheck /usr/local/bin/govulncheck

# ffuf content-discovery wordlist (SecLists common.txt). Not packaged for
# Ubuntu, so fetch the single list to the path the ffuf wrapper defaults to.
RUN . /usr/local/bin/ts_want.sh \
    && if ts_want web; then \
       mkdir -p /usr/share/seclists/Discovery/Web-Content \
       && curl -fL -o /usr/share/seclists/Discovery/Web-Content/common.txt \
       https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
       || echo "seclists common.txt fetch failed (non-fatal; pass an explicit ffuf wordlist arg)" ; \
    else echo "skip seclists (TOOLSET=$TS_TOOLSET)"; fi

# kiterunner API-route wordlist (assetnote routes-small). Escalation-only,
# so the small list keeps the image lean.
RUN . /usr/local/bin/ts_want.sh \
    && if ts_want api; then \
       mkdir -p /usr/share/kiterunner \
       && curl -fL -o /tmp/routes-small.kite.tar.gz \
       https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz \
       && tar -xzf /tmp/routes-small.kite.tar.gz -C /usr/share/kiterunner \
       && rm -f /tmp/routes-small.kite.tar.gz \
       || echo "kiterunner wordlist fetch failed (non-fatal; pass an explicit wordlist arg)" ; \
    else echo "skip kiterunner wordlist (TOOLSET=$TS_TOOLSET)"; fi

# CodeQL CLI + query bundle (repository escalation, E3 — interprocedural
# taint). Large (~hundreds of MB); escalation-only, fired only when semgrep
# flags an injection candidate. Pinned bundle for reproducibility (§10).
# THIS FETCH WAS 404-ing AND THE BUILD SWALLOWED IT. The release publishes codeql-linux64.ZIP; this
# asked for .tar.gz, got a 404, and `|| echo "non-fatal"` turned that into a successful build. codeql
# has never been in the image at this pin — so the repository asset shipped without its taint-analysis
# escalation, and `tsengine tool-freshness` reported codeql "pinned 2.20.3", asserting a version for a
# binary that was not there. Same defect class as a scanner that cannot reach its DB reporting a clean
# scan: a failure swallowed into a success.
#
# codeql publishes ONE linux build and it is x86_64 ONLY — there is no arm64 CLI. The old CQ_ARCH
# ternary printed linux64 in BOTH branches, which dressed that fact up as arch handling and hid it.
# Measured on an arm64 build with the URL fixed: the 469MB download and unzip both succeed, then
# `codeql version` dies with "Trace/breakpoint trap" — an x86_64 binary under emulation. So on arm64
# it is STUBBED rather than installed broken: the stub exits 127, tool.DidNotRun reports "did not
# run", and the repository escalation lands in ToolsFailed saying so. An unrunnable binary on $PATH
# would instead fail at scan time with an error nobody could map back to the image's architecture.
ARG CODEQL_VERSION=2.20.3
RUN . /usr/local/bin/ts_want.sh \
    && if ! ts_want repository; then echo "skip codeql (TOOLSET=$TS_TOOLSET)"; \
    elif [ "${TARGETARCH}" != "amd64" ]; then \
       echo "codeql: no arm64 CLI upstream — stubbing (taint escalation unavailable on this arch)"; \
       printf '#!/bin/sh\necho "codeql is not installed in this image (upstream ships no arm64 CLI; build for linux/amd64 to get the taint-analysis escalation)." >&2\nexit 127\n' > /usr/local/bin/codeql \
       && chmod +x /usr/local/bin/codeql; \
    else \
       curl -fL --retry 3 --retry-delay 2 -o /tmp/codeql.zip \
       "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
       && unzip -q /tmp/codeql.zip -d /opt \
       && ln -sf /opt/codeql/codeql /usr/local/bin/codeql \
       && rm -f /tmp/codeql.zip \
       && /opt/codeql/codeql version --format=terse \
       || { echo "FATAL: codeql install failed on amd64, where it is supposed to work. The repository asset would lose its taint-analysis escalation and nothing downstream would say so." >&2; exit 1; } ; \
    fi

# KICS (deeper IaC SAST, repository registry-tier). THREE bugs here, all silent:
#
#  1. v2.1.3 publishes NO platform binaries at all (only extracted-info.zip), so the URL 404'd.
#  2. The arch string was wrong anyway — releases use linux_amd64, not linux_x64.
#  3. The comment claimed the tarball "bundles the kics binary + its assets/queries corpus".
#     IT DOES NOT: the archive holds LICENSE, README and the binary, nothing else. kics without its
#     queries runs and finds nothing — a scanner reporting clean because it has no rules, which is
#     worse than a scanner that is absent, because an absent one is reported in ToolsFailed.
#
# So the queries come from the SOURCE archive for the same tag (17,928 files), extracted next to the
# binary where kics looks for them. Pinned together so the corpus and the binary always match.
ARG KICS_VERSION=2.1.20
RUN . /usr/local/bin/ts_want.sh \
    && if ts_want repository; then \
       mkdir -p /opt/kics \
       && curl -fL --retry 3 --retry-delay 2 -o /tmp/kics.tar.gz \
       "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_${TARGETARCH}.tar.gz" \
       && tar -xzf /tmp/kics.tar.gz -C /opt/kics \
       && curl -fL --retry 3 --retry-delay 2 -o /tmp/kics-src.tar.gz \
       "https://github.com/Checkmarx/kics/archive/refs/tags/v${KICS_VERSION}.tar.gz" \
       && tar -xzf /tmp/kics-src.tar.gz -C /tmp "kics-${KICS_VERSION}/assets/queries" \
       && mv "/tmp/kics-${KICS_VERSION}/assets" /opt/kics/assets \
       && ln -sf /opt/kics/kics /usr/local/bin/kics \
       && rm -rf /tmp/kics.tar.gz /tmp/kics-src.tar.gz "/tmp/kics-${KICS_VERSION}" \
       && /opt/kics/kics version \
       && [ "$(find /opt/kics/assets/queries -name '*.rego' | head -1)" ] \
       || { echo "FATAL: kics install failed (binary or query corpus missing). kics without queries reports a clean scan because it has no rules." >&2; exit 1; } ; \
    else echo "skip kics (TOOLSET=$TS_TOOLSET)"; fi

# Set unconditionally: the path is harmless when kics was not installed, and keeping it out of the
# gated RUN avoids an ENV inside a shell conditional (which Docker cannot parse).
ENV KICS_QUERIES_PATH=/opt/kics/assets/queries

# syft (SBOM) + hadolint (Dockerfile lint) via release artifacts. syft's
# install script is anchore's recommended path; hadolint ships per-arch
# static binaries (Linux-x86_64 / Linux-arm64).
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sh -s -- -b /usr/local/bin \
    && HADOLINT_ARCH="$([ "${TARGETARCH}" = "amd64" ] && echo x86_64 || echo arm64)" \
    && curl -fL -o /usr/local/bin/hadolint \
        "https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-${HADOLINT_ARCH}" \
    && chmod +x /usr/local/bin/hadolint

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


# ---------------------------------------------------------------------------
# THE IMAGE MUST CONTAIN WHAT IT CLAIMS TO. Last step on purpose: everything is installed by now, and
# a missing scanner should break the build here rather than surface months later as a degraded
# customer scan. This is what codeql and kics needed and did not have — see verify-tools.sh.
# ---------------------------------------------------------------------------
# --chmod on the COPY, not a chmod in the RUN: by this point the stage has dropped to a non-root
# user, so `chmod` is "Operation not permitted" and the build dies on the guard rather than on
# anything it was guarding.
COPY --chmod=0755 docker/sandbox/verify-tools.sh /usr/local/bin/verify-tools.sh
RUN /usr/local/bin/verify-tools.sh

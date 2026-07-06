# tsengine build + dev tasks.
# All targets are .PHONY because we don't track outputs as Make
# dependencies — Go tooling handles its own caching.

SANDBOX_IMAGE ?= tsengine/sandbox:0.1.0
HOST_IMAGE    ?= tsengine/host:dev
NUCLEI_VERSION ?= 3.3.7

# Version stamped into the binary (overrides main.Version). Defaults to the git
# describe so local/dev builds self-identify; CI release passes the tag.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)

GOFLAGS ?=
GOTESTFLAGS ?= -race -count=1

.PHONY: all
all: build test vet

.PHONY: build
build: ## build all Go packages
	go build $(GOFLAGS) ./...

.PHONY: test
test: ## run all Go tests
	go test $(GOTESTFLAGS) ./...

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: lint
lint: ## golangci-lint (requires golangci-lint installed)
	golangci-lint run

.PHONY: cli
cli: ## build the host CLI binary into ./bin/ (version-stamped)
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o ./bin/tsengine ./cmd/tsengine

.PHONY: serve
serve: cli ## run the long-running service locally (set TSENGINE_API_TOKEN)
	./bin/tsengine serve

.PHONY: host-image
host-image: ## build the host service docker image (tsengine serve)
	docker build \
		--build-arg VERSION=$(VERSION) \
		-t $(HOST_IMAGE) \
		-f docker/host/Dockerfile .

.PHONY: sandbox-image
sandbox-image: ## build the sandbox docker image
	docker build \
		--build-arg NUCLEI_VERSION=$(NUCLEI_VERSION) \
		-t $(SANDBOX_IMAGE) \
		-f docker/sandbox/Dockerfile .

.PHONY: sandbox-shell
sandbox-shell: ## drop into a shell in a one-off sandbox container (for debugging)
	docker run --rm -it --entrypoint /bin/bash $(SANDBOX_IMAGE)

.PHONY: demo
demo: cli sandbox-image ## end-to-end: build cli + image, scan a benign target
	./bin/tsengine scan \
		--asset web_application \
		--target https://example.com \
		--image $(SANDBOX_IMAGE)

.PHONY: tsbench
tsbench: ## build the bench harness binary into ./bin/
	mkdir -p bin
	go build -o ./bin/tsbench ./cmd/tsbench

.PHONY: bench
bench: cli tsbench sandbox-image ## run the runnable L1 benchmarks
	./bin/tsbench run --fixture fixtures/container/nginx-vuln
	./bin/tsbench run --fixture fixtures/container/alpine-clean
	./bin/tsbench run --fixture fixtures/repo/sca-vuln

.PHONY: bench-ablation
bench-ablation: cli tsbench sandbox-image ## run the L1.5 ablation on the container fixture
	./bin/tsbench ablation --fixture fixtures/container/nginx-vuln

.PHONY: bench-engineer
bench-engineer: cli tsbench ## AI Security Engineer benchmark — deterministic checks (unit + calibration + impact discrimination). Live per-category scoring needs an LLM key (see bench/AI-SECURITY-ENGINEER-BENCHMARK.md)
	@echo "→ unit: verdict/impact/patch scorers + anti-overfit guard"
	go test ./internal/bench/ ./internal/codeagent/ ./cmd/tsbench/
	@echo "→ calibration on a real container (needs Docker): correct→remediated, no-op→ineffective, breaking→broke_app"
	go test -tags=integration -run DefenseXBOWSelftest ./cmd/tsbench/
	@echo "→ impact discrimination: the substrate-only baseline must NOT pass the mis-tagged estate"
	./bin/tsbench impact --scenario fixtures/impact/estate-mistagged.json --naive-baseline

.PHONY: up
up: ## bring up the full product stack (platform API + frontend) via docker compose
	docker compose up --build -d
	@echo "→ console http://localhost:3000 (sign up at /signup) · API http://localhost:8090"

.PHONY: down
down: ## stop the product stack
	docker compose down

.PHONY: deploy-prod
deploy-prod: ## production single-box deploy (hardened stack: TLS edge + socket-proxy + engine)
	./scripts/deploy-single-box.sh

.PHONY: backup
backup: ## back up the platform-data volume to ./backups
	./scripts/backup.sh

.PHONY: prod-validate
prod-validate: ## validate the hardened single-box stack (compose + Caddyfile) without secrets
	@TSENGINE_SECRET_KEY=validate TSENGINE_PLATFORM_TOKEN=validate \
		docker compose -f docker-compose.prod.yml config -q && echo "✓ docker-compose.prod.yml valid"
	@docker run --rm -e TSENGINE_SITE_ADDRESS=localhost \
		-v "$(PWD)/docker/caddy/Caddyfile:/etc/caddy/Caddyfile:ro" \
		caddy:2-alpine caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
		&& echo "✓ Caddyfile valid"

.PHONY: platform-image
platform-image: ## build the platform server image
	docker build -t tsengine/platform:dev -f docker/platform/Dockerfile .

.PHONY: frontend-image
frontend-image: ## build the frontend image
	docker build -t tsengine/frontend:dev frontend/

.PHONY: dev
dev: ## run the local demo stack (platform + frontend) with a CLEAN Next cache — fixes "unstyled" app
	./scripts/dev.sh

.PHONY: dev-reseed
dev-reseed: ## refresh demo data to current code, then (re)start the stack — drops + re-seeds the DB
	@$(MAKE) dev-down
	@RESEED=1 ./scripts/dev.sh

.PHONY: demo-secure
demo-secure: ## run the demo with the ENGINE ON + hardened Docker sandboxes (one asset of every type)
	./scripts/demo-secure.sh

.PHONY: demo-scan-asset
demo-scan-asset: ## prove the secure-Docker scan path per asset type (container + repo, no creds)
	./scripts/demo-scan-asset.sh

.PHONY: dev-down
dev-down: ## stop the local dev stack (frees :3000 and :8090)
	@pkill -f 'next dev' 2>/dev/null || true; pkill -f 'next-server' 2>/dev/null || true
	@for p in 8090 3000; do pids=$$(lsof -nP -iTCP:$$p -sTCP:LISTEN -t 2>/dev/null); [ -n "$$pids" ] && kill -9 $$pids 2>/dev/null || true; done
	@echo "→ dev stack stopped"

.PHONY: clean
clean: ## remove build artifacts
	rm -rf bin/ runs/

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

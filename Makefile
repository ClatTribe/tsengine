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

.PHONY: bench-ablation
bench-ablation: cli tsbench sandbox-image ## run the L1.5 ablation on the container fixture
	./bin/tsbench ablation --fixture fixtures/container/nginx-vuln

.PHONY: up
up: ## bring up the full product stack (platform API + frontend) via docker compose
	docker compose up --build -d
	@echo "→ console http://localhost:3000 (sign up at /signup) · API http://localhost:8090"

.PHONY: down
down: ## stop the product stack
	docker compose down

.PHONY: platform-image
platform-image: ## build the platform server image
	docker build -t tsengine/platform:dev -f docker/platform/Dockerfile .

.PHONY: frontend-image
frontend-image: ## build the frontend image
	docker build -t tsengine/frontend:dev frontend/

.PHONY: clean
clean: ## remove build artifacts
	rm -rf bin/ runs/

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

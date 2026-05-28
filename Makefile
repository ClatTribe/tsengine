# tsengine build + dev tasks.
# All targets are .PHONY because we don't track outputs as Make
# dependencies — Go tooling handles its own caching.

SANDBOX_IMAGE ?= tsengine/sandbox:0.1.0
NUCLEI_VERSION ?= 3.3.7

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
cli: ## build the host CLI binary into ./bin/
	mkdir -p bin
	go build -o ./bin/tsengine ./cmd/tsengine

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

.PHONY: clean
clean: ## remove build artifacts
	rm -rf bin/ runs/

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

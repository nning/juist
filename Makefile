# wg-p2p — developer and CI entry points.
#
# CI (.github/workflows/ci.yml) invokes these same targets, so `make check`
# passing locally means CI passes too. Keep it that way: put new gates here
# first and have the workflow call them.
#
# Run `make` or `make help` for the target list.

GO      ?= go
GOFLAGS ?=

# Tool versions are pinned so local runs and CI agree, and so a compromised or
# simply changed upstream cannot silently alter what our gates check. Bump
# these deliberately.
STATICCHECK_VERSION ?= v0.8.1
GOVULNCHECK_VERSION ?= v1.7.0
ACTIONLINT_VERSION  ?= v1.7.7

# Source directories resolved through the module rather than by walking the
# tree, so unrelated checkouts (agent worktrees under .claude/, vendored
# scratch copies) are never formatted, linted, or tested.
GO_PKG_DIRS = $(shell $(GO) list -f '{{.Dir}}' ./...)

# Platforms v1 commits to (docs/05-roadmap.md M5). Building for each catches
# build-tag rot in the embedded Tailscale stack long before the platform work
# starts.
CROSS_PLATFORMS ?= linux/amd64 linux/arm64 freebsd/amd64 android/arm64

# -count=1 defeats the test cache: several tests here assert on external state
# (open sockets, /proc) that the cache cannot see.
TEST_FLAGS   ?= -count=1 -timeout 15m
COVERPROFILE ?= coverage.out

# Per-target fuzzing budget for the CI smoke run. The real 72 CPU-hour gates
# described in docs/06-verification.md are a separate, longer-running job.
FUZZTIME ?= 30s

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

## --- build ---------------------------------------------------------------

.PHONY: build
build: ## Compile all packages
	$(GO) build $(GOFLAGS) ./...

.PHONY: cross
cross: ## Compile for every v1 target platform
	@for p in $(CROSS_PLATFORMS); do \
		echo "==> $$p"; \
		CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} $(GO) build $(GOFLAGS) ./... || exit 1; \
	done

## --- test ----------------------------------------------------------------

.PHONY: test
test: ## Run tests
	$(GO) test $(GOFLAGS) ./... $(TEST_FLAGS)

.PHONY: test-race
test-race: ## Run tests under the race detector
	$(GO) test $(GOFLAGS) ./... $(TEST_FLAGS) -race

.PHONY: cover
cover: ## Run race tests with coverage, print a summary
	$(GO) test $(GOFLAGS) ./... $(TEST_FLAGS) -race \
		-covermode=atomic -coverprofile=$(COVERPROFILE)
	@$(GO) tool cover -func=$(COVERPROFILE) | tail -n 1

.PHONY: cover-html
cover-html: cover ## Open the coverage report in a browser
	$(GO) tool cover -html=$(COVERPROFILE)

.PHONY: fuzz
fuzz: ## Smoke-run every fuzz target for FUZZTIME
	@found=0; \
	for pkg in $$($(GO) list ./...); do \
		for target in $$($(GO) test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
			found=1; \
			echo "==> $$pkg $$target ($(FUZZTIME))"; \
			$(GO) test $$pkg -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZTIME) || exit 1; \
		done; \
	done; \
	if [ $$found -eq 0 ]; then \
		echo "no fuzz targets yet; see docs/06-verification.md for the planned ones"; \
	fi

## --- lint ----------------------------------------------------------------

.PHONY: fmt
fmt: ## Format the source tree
	gofmt -w -l $(GO_PKG_DIRS)

.PHONY: fmt-check
fmt-check: ## Fail if any file is unformatted
	@unformatted=$$(gofmt -l $(GO_PKG_DIRS)); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt'd:"; echo "$$unformatted"; \
		echo "run: make fmt"; \
		exit 1; \
	fi

.PHONY: vet
vet: ## Run go vet
	$(GO) vet $(GOFLAGS) ./...

.PHONY: staticcheck
staticcheck: ## Run staticcheck
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

.PHONY: govulncheck
govulncheck: ## Check dependencies against the Go vulnerability database
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

.PHONY: actionlint
actionlint: ## Lint the GitHub Actions workflows
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

.PHONY: lint
lint: fmt-check vet staticcheck actionlint ## Run all static analysis

## --- modules -------------------------------------------------------------

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	$(GO) mod tidy

.PHONY: tidy-check
tidy-check: ## Fail if go.mod / go.sum are untidy (does not modify them)
	@cp go.mod go.mod.check.bak; cp go.sum go.sum.check.bak; \
	trap 'mv -f go.mod.check.bak go.mod; mv -f go.sum.check.bak go.sum' EXIT; \
	$(GO) mod tidy || exit 1; \
	if ! cmp -s go.mod go.mod.check.bak || ! cmp -s go.sum go.sum.check.bak; then \
		echo "go.mod/go.sum are not tidy; run: make tidy"; \
		exit 1; \
	fi

## --- aggregate -----------------------------------------------------------

.PHONY: check
check: lint tidy-check build test-race ## Everything CI gates on; run before pushing

.PHONY: clean
clean: ## Remove build and test artifacts
	rm -f $(COVERPROFILE) wgp2p wgp2pd
	$(GO) clean -testcache

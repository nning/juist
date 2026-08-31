# juist — developer and CI entry points.
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

# Where `make build` puts the binaries, and the commands it builds — each is
# ./cmd/<name>, written to $(BUILDDIR)/<name>. A directory rather than the repo
# root so the tree gains one ignorable path instead of one per command, and so
# `clean` is a single rm that cannot reach a source file.
BUILDDIR ?= build
CMDS     ?= juist juistd

# Platforms v1 commits to (docs/05-roadmap.md M5). Building for each catches
# build-tag rot in the embedded Tailscale stack long before the platform work
# starts.
CROSS_PLATFORMS ?= linux/amd64 linux/arm64 freebsd/amd64 android/arm64

# -count=1 defeats the test cache: several tests here assert on external state
# (open sockets, /proc) that the cache cannot see.
TEST_FLAGS   ?= -count=1 -timeout 15m
COVERPROFILE ?= coverage.out

# Per-target fuzzing budget for the smoke run. The milestone gate is
# `fuzz-long`, which docs/06-verification.md sets at 72 clean CPU-hours per
# input surface.
FUZZTIME ?= 30s

# Wall-clock budget and worker count for one target's `fuzz-long` run. The gate
# is 72 CPU-hours *per input surface*, and the two knobs multiply: 6h x 4
# workers is 24 CPU-hours per target per run, so the corpus reaches the gate
# over three preserved runs. Fuzzing does not run on CI at all — hours per input
# surface is far more hosted-runner time than this project is willing to spend
# — so the gate is run by hand before a milestone closes. Do not run every
# target in one sequential pass on a machine you cannot leave alone for days:
# a fixed iteration order starves the last targets (the trust-layer ones) of
# any time at all, which is how this was found on CI. Prefer `fuzz-one` per
# target, listed by `fuzz-matrix`, each with its own preserved corpus. Match
# the worker count to real cores; more workers than cores buys no throughput.
FUZZLONGTIME    ?= 6h
FUZZLONGWORKERS ?= 4

# The trusted computing base: the audit scope in docs/06-verification.md, whose
# size is a tracked regression metric with a 10k-line budget.
TCB_PKGS ?= ./types ./trust/...

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

## --- build ---------------------------------------------------------------

# .PHONY is load-bearing here: the target's name is also $(BUILDDIR)'s, and
# without it make would call `build` up to date the moment the directory exists.
# Deciding what is stale is left to the Go build cache, which knows the
# dependency graph make would have to be told.
.PHONY: build
build: ## Build the binaries into build/
	@mkdir -p $(BUILDDIR)
	@for c in $(CMDS); do \
		echo "==> $(BUILDDIR)/$$c"; \
		$(GO) build $(GOFLAGS) -o $(BUILDDIR)/$$c ./cmd/$$c || exit 1; \
	done

# The compile gate, and only that: `go build` over more than one package
# discards what it produces, so this writes no binaries — which is the point,
# since `check` wants to know the tree compiles, not to leave artifacts behind.
# It covers the packages `build` never links in: libraries with no command
# above them, whose first sign of breakage would otherwise be a failing test.
.PHONY: build-test
build-test: ## Compile every package as a check, producing no binaries
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

.PHONY: fuzz-long
fuzz-long: ## Run the milestone fuzz gate over every target in turn (long; local use)
	@for pkg in $$($(GO) list ./...); do \
		for target in $$($(GO) test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
			$(MAKE) --no-print-directory fuzz-one FUZZPKG=$$pkg FUZZTARGET=$$target || exit 1; \
		done; \
	done

.PHONY: fuzz-one
fuzz-one: ## Fuzz one target: make fuzz-one FUZZPKG=<import path> FUZZTARGET=<FuzzName>
	@test -n "$(FUZZPKG)" || { echo "fuzz-one: set FUZZPKG to a package import path"; exit 2; }
	@test -n "$(FUZZTARGET)" || { echo "fuzz-one: set FUZZTARGET to a Fuzz function name"; exit 2; }
	@echo "==> $(FUZZPKG) $(FUZZTARGET) ($(FUZZLONGTIME) x $(FUZZLONGWORKERS) workers)"
	$(GO) test $(FUZZPKG) -run '^$$' -fuzz "^$(FUZZTARGET)$$" \
		-fuzztime $(FUZZLONGTIME) -parallel $(FUZZLONGWORKERS)

# fuzz-matrix emits the fuzz targets as a compact JSON array, one object per
# target: {"pkg","target","name"}. Use it to drive the gate one target at a
# time rather than the sequential pass `fuzz-long` makes; "name" is a
# slash-free label suitable for a per-target corpus directory.
.PHONY: fuzz-matrix
fuzz-matrix: ## Emit the fuzz targets as a JSON matrix (one object per target)
	@first=1; printf '['; \
	for pkg in $$($(GO) list ./...); do \
		for target in $$($(GO) test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
			[ $$first -eq 1 ] || printf ','; first=0; \
			printf '{"pkg":"%s","target":"%s","name":"%s-%s"}' \
				"$$pkg" "$$target" "$$(basename $$pkg)" "$$target"; \
		done; \
	done; \
	printf ']\n'

.PHONY: tcb
tcb: ## Report the trusted computing base's size against its budget
	@lines=$$($(GO) list -f '{{$$d := .Dir}}{{range .GoFiles}}{{$$d}}/{{.}} {{end}}' $(TCB_PKGS) \
		| tr ' ' '\n' | grep -v '^$$' | xargs cat | wc -l); \
	echo "TCB: $$lines lines across $(TCB_PKGS) (budget 10000, docs/06-verification.md)"; \
	if [ "$$lines" -gt 10000 ]; then \
		echo "over budget: the audit scope has grown past what docs/06-verification.md plans for"; \
		exit 1; \
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
check: lint tidy-check build-test test-race tcb ## Everything CI gates on; run before pushing

.PHONY: clean
clean: ## Remove build and test artifacts
	rm -rf $(BUILDDIR)
	rm -f $(COVERPROFILE)
	$(GO) clean -testcache

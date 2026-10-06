# juist — developer and CI entry points.
#
# CI (.github/workflows/ci.yml) invokes these same targets, so `make check`
# passing locally means CI passes too. Keep it that way: put new gates here
# first and have the workflow call them.
#
# Run `make` or `make help` for the target list.

GO      ?= go
GOFLAGS ?=

# One toolchain for every target, so a commit builds to the same bytes anywhere
# and local runs match CI's GO_VERSION.
export GOTOOLCHAIN ?= go1.27.1

# Static binaries that need no C toolchain; only the race detector wants cgo.
export CGO_ENABLED ?= 0

# How every shipped binary is built; `make repro` checks it is reproducible.
GOBUILD = CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath

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

# Platforms the roadmap commits to (docs/05-roadmap.md M7, M10). Building for each catches
# build-tag rot in the embedded Tailscale stack long before the platform work
# starts.
CROSS_PLATFORMS ?= linux/amd64 linux/arm64 freebsd/amd64 android/arm64
# Platforms kept compiling though nothing ships for them: macOS, deferred past v1.
CROSS_UNSHIPPED ?= darwin/arm64

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
# bindir is where the packages build GOOS $(1) and GOARCH $(2)'s binaries:
# build/ itself for this system's, as `build` leaves them, so that go finds
# them up to date and relinks nothing; build/GOOS-GOARCH for another's.
bindir = $(if $(filter $(shell $(GO) env GOOS)/$(shell $(GO) env GOARCH),$(1)/$(2)),$(BUILDDIR),$(BUILDDIR)/$(1)-$(2))

.PHONY: build
build: ## Build the binaries into build/
	@mkdir -p $(BUILDDIR)
	@for c in $(CMDS); do \
		echo "==> $(BUILDDIR)/$$c"; \
		$(GOBUILD) -o $(BUILDDIR)/$$c ./cmd/$$c || exit 1; \
	done

# The man pages are made by the commands themselves, from their own help, so
# they say what the commands say: juist(1) and juistd(8).
MANDIR ?= $(BUILDDIR)/man

.PHONY: man
man: ## Build the man pages, juist(1) and juistd(8), into build/man
	@mkdir -p $(MANDIR)
	$(GO) run $(GOFLAGS) ./cmd/juist __manpage > $(MANDIR)/juist.1
	$(GO) run $(GOFLAGS) ./cmd/juistd __manpage > $(MANDIR)/juistd.8

# The compile gate, and only that: `go build` over more than one package
# discards what it produces, so this writes no binaries — which is the point,
# since `check` wants to know the tree compiles, not to leave artifacts behind.
# It covers the packages `build` never links in: libraries with no command
# above them, whose first sign of breakage would otherwise be a failing test.
.PHONY: build-test
build-test: ## Compile every package as a check, producing no binaries
	$(GO) build $(GOFLAGS) ./...

.PHONY: cross
cross: ## Compile for every v1 target platform, and macOS
	@for p in $(CROSS_PLATFORMS) $(CROSS_UNSHIPPED); do \
		echo "==> $$p"; \
		CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} $(GO) build $(GOFLAGS) ./... || exit 1; \
	done
	@echo "==> FreeBSD's manual pages, here"; $(GO) build $(GOFLAGS) -tags freebsdman ./cmd/...
	@echo "==> darwin's tests, which run nowhere"; CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) vet $(GOFLAGS) ./...

# HEAD built twice, from two paths and once with an empty build cache, so
# neither the checkout's location nor a cached object can hide a difference.
.PHONY: repro
repro: ## Fail unless HEAD builds to the same binaries twice
	@set -e; tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	git clone -q . "$$tmp/a"; git clone -q . "$$tmp/elsewhere/b"; \
	for c in $(CMDS); do \
		(cd "$$tmp/a" && $(GOBUILD) -o "$$tmp/out-a/$$c" ./cmd/$$c); \
		(cd "$$tmp/elsewhere/b" && GOCACHE="$$tmp/cache" $(GOBUILD) -o "$$tmp/out-b/$$c" ./cmd/$$c); \
		cmp -s "$$tmp/out-a/$$c" "$$tmp/out-b/$$c" || { echo "repro: two builds of $$c differ"; exit 1; }; \
		echo "==> $$c reproducible"; \
	done

## --- test ----------------------------------------------------------------

.PHONY: test
test: ## Run tests
	$(GO) test $(GOFLAGS) ./... $(TEST_FLAGS)

.PHONY: test-race
test-race: ## Run tests under the race detector
	CGO_ENABLED=1 $(GO) test $(GOFLAGS) ./... $(TEST_FLAGS) -race

# The privileged tests — M3a's real device and netns harness, and M3b's NAT
# matrix on top of it (conn/osplumbing_test.go, conn/netns*_linux_test.go) —
# need root, /dev/net/tun, iproute2 and iptables, and skip without them — which
# `test` and `cover` do silently. This target runs them
# alone, verbosely, with the skip turned into a failure, so a machine that
# cannot create a device or a namespace reports red rather than green. Run it
# under sudo; `go` is resolved before privileges change, and the module and
# build caches stay with the invoking user. The netns harness re-executes its
# own test binary inside each namespace, which a compiled one is as much as
# `go test`'s: test-os-plumbing-sudo relies on that.
PLUMBING_TESTS = ^(TestRealDevicePlumbsOverlayIntoHost|TestNetns.*)$$

.PHONY: test-os-plumbing
test-os-plumbing: ## Run the privileged real-device and netns tests (use sudo)
	JUIST_REQUIRE_OS_PLUMBING=1 $(GO) test $(GOFLAGS) ./conn $(TEST_FLAGS) -v \
		-run '$(PLUMBING_TESTS)'

# The same tests compiled as the invoking user and only the binary run as
# root, so no root-owned file lands in the user's Go caches — which running
# `go` itself under sudo does on a desktop.
.PHONY: test-os-plumbing-sudo
test-os-plumbing-sudo: ## Build the privileged tests as you, run them with sudo
	$(GO) test $(GOFLAGS) -c -o $(abspath $(BUILDDIR))/conn.test ./conn
	cd conn && sudo JUIST_REQUIRE_OS_PLUMBING=1 $(abspath $(BUILDDIR))/conn.test \
		-test.count=1 -test.timeout=15m -test.v -test.run '$(PLUMBING_TESTS)'

# Every package's tests, built here for FreeBSD and run on a FreeBSD host as
# root, the OS plumbing required. FREEBSD_SSH reaches it; the default is a
# qemu VM with its ssh forwarded to 2222, as docs/12-validating.md sets up.
FREEBSD_SSH ?= ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p 2222 root@127.0.0.1

# HEAD built here and on a FreeBSD host (FREEBSD_SSH), for Linux and FreeBSD:
# two builders on two systems making the same bytes.
.PHONY: repro-freebsd
repro-freebsd: ## Fail unless a FreeBSD host builds HEAD to the same binaries as this one
	sh packaging/freebsd/repro.sh "$(GO)" "$(FREEBSD_SSH)" "$(GOTOOLCHAIN)"

# The interop lab, interop/: a Debian and a FreeBSD VM in qemu with the
# packages, each the other's exit node and subnet router. KVM where /dev/kvm
# opens, TCG, far slower, elsewhere; the images are fetched into
# INTEROP_CACHE once and checked against their pinned sums.
INTEROP_CACHE ?= $(HOME)/.cache/juist-interop
# The browser the lab fetches over HTTP/3 with, headless.
INTEROP_CHROME ?= $(firstword $(shell command -v chromium chromium-browser google-chrome chrome 2>/dev/null))

.PHONY: interop
interop: deb pkg-freebsd image ## Run the Linux/FreeBSD lab in qemu, without root (needs qemu, xz, ssh, Chrome)
	cd interop && JUIST_INTEROP_WORK=$(abspath $(BUILDDIR))/interop \
		JUIST_INTEROP_DEB=$$(find $(DEBTOP) -maxdepth 1 -name '*.deb') \
		JUIST_INTEROP_PKG=$$(find $(abspath $(BUILDDIR))/freebsd -name '*.pkg') \
		JUIST_INTEROP_IMAGE=$$(find $(abspath $(BUILDDIR))/image -name 'juist-*-$(IMAGE_ARCH).tar' | head -1) \
		JUIST_INTEROP_CACHE=$(INTEROP_CACHE) JUIST_INTEROP_CHROME=$(INTEROP_CHROME) GO=$(GO) \
		$(GO) test $(GOFLAGS) -tags interop -count=1 -timeout 150m -v .

# agg renders the cast as a GIF: https://github.com/asciinema/agg
AGG       ?= agg
AGG_FLAGS ?= --font-size 14

.PHONY: demo
demo: deb pkg-freebsd ## Record the README's demo in the lab, into website/static/demo.{cast,gif}
	cd interop && JUIST_INTEROP_WORK=$(abspath $(BUILDDIR))/demo \
		JUIST_INTEROP_DEB=$$(find $(DEBTOP) -maxdepth 1 -name '*.deb') \
		JUIST_INTEROP_PKG=$$(find $(abspath $(BUILDDIR))/freebsd -name '*.pkg') \
		JUIST_INTEROP_CACHE=$(INTEROP_CACHE) JUIST_DEMO_CAST=$(abspath website/static/demo.cast) GO=$(GO) \
		$(GO) test $(GOFLAGS) -tags interop -count=1 -timeout 60m -run TestDemo -v .
	$(AGG) $(AGG_FLAGS) --theme asciinema website/static/demo.cast website/static/demo.gif

# The website under load: visitors as browsers come, LOAD_RATE a second for
# LOAD_FOR. load-site loads its server alone, here; load-lab loads it in the
# lab behind an ingress and the tunnel, as it is published.
LOAD_RATE ?= 20
LOAD_FOR  ?= 90s

.PHONY: load-site
load-site: ## Load the website's server alone, here
	$(MAKE) -C website site
	cd website && $(GO) build -o $(abspath $(BUILDDIR))/site-server ./server
	$(GO) build -o $(BUILDDIR)/probe ./interop/probe
	@$(BUILDDIR)/site-server -root $(abspath $(BUILDDIR))/site -addr 127.0.0.1:18181 2>/dev/null & pid=$$!; \
	trap 'kill $$pid' EXIT; sleep 1; \
	$(BUILDDIR)/probe visitors -rate $(LOAD_RATE) -for $(LOAD_FOR) -hold 30s http://127.0.0.1:18181/en/

.PHONY: load-lab
load-lab: deb pkg-freebsd ## Load the website in the lab, through an ingress and the tunnel (qemu)
	$(MAKE) -C website site
	tar -czf $(BUILDDIR)/site.tgz -C $(BUILDDIR) site
	cd website && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(abspath $(BUILDDIR))/site-server-linux ./server
	cd interop && JUIST_INTEROP_WORK=$(abspath $(BUILDDIR))/load \
		JUIST_INTEROP_DEB=$$(find $(DEBTOP) -maxdepth 1 -name '*.deb') \
		JUIST_INTEROP_PKG=$$(find $(abspath $(BUILDDIR))/freebsd -name '*.pkg') \
		JUIST_INTEROP_CACHE=$(INTEROP_CACHE) GO=$(GO) \
		JUIST_LOAD_SITE=$(abspath $(BUILDDIR))/site.tgz JUIST_LOAD_SERVER=$(abspath $(BUILDDIR))/site-server-linux \
		JUIST_LOAD_RATE=$(LOAD_RATE) JUIST_LOAD_FOR=$(LOAD_FOR) \
		$(GO) test $(GOFLAGS) -tags interop -count=1 -timeout 60m -run TestLoad -v .

# Pebble is Let's Encrypt's test CA. It runs on this machine alone; nothing
# here talks to a real CA.
PEBBLE_VERSION ?= v2.10.1

.PHONY: test-acme
test-acme: ## Run the TLS terminator against Pebble, an ACME CA of its own
	GOBIN=$(abspath $(BUILDDIR)) $(GO) install github.com/letsencrypt/pebble/v2/cmd/pebble@$(PEBBLE_VERSION)
	JUIST_PEBBLE=$(abspath $(BUILDDIR))/pebble $(GO) test $(GOFLAGS) $(TEST_FLAGS) -run TestACertificateFromPebble -v ./internal/terminator

.PHONY: test-freebsd
test-freebsd: ## Run every test on a FreeBSD host over ssh, as root (FREEBSD_SSH)
	sh packaging/freebsd/test.sh "$(GO)" "$(FREEBSD_SSH)"

.PHONY: cover
cover: ## Run race tests with coverage, print a summary
	CGO_ENABLED=1 $(GO) test $(GOFLAGS) ./... $(TEST_FLAGS) -race \
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

## --- android -------------------------------------------------------------

# The app (android/) is Kotlin around the core in ./mobile, which gomobile
# binds into an AAR for the phone and the emulator. Needs a JDK and the
# Android SDK and NDK: ANDROID_HOME, and ANDROID_NDK_HOME or the NDK in it.
ANDROID_AAR    = $(BUILDDIR)/android/juist-core.aar
ANDROID_API    ?= 31
ANDROID_TARGET ?= android/arm64,android/amd64
GRADLE          = cd android && ./gradlew --no-daemon -q

.PHONY: android-core
android-core: ## Bind the core in ./mobile into an AAR for the Android app
	@mkdir -p $(BUILDDIR)/tools $(BUILDDIR)/android/assets
	$(GO) build -o $(BUILDDIR)/tools/ golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
	PATH="$(abspath $(BUILDDIR)/tools):$$PATH" CGO_ENABLED=1 $(BUILDDIR)/tools/gomobile bind -target $(ANDROID_TARGET) \
		-androidapi $(ANDROID_API) -javapkg io.juist -trimpath -ldflags="-s -w -buildid=" -o $(ANDROID_AAR) ./mobile
	@cat THIRD_PARTY_LICENSES "$$($(GO) list -m -f '{{.Dir}}' golang.org/x/mobile)/LICENSE" \
		android/THIRD_PARTY_NOTICES > $(BUILDDIR)/android/assets/licenses.txt

.PHONY: android
android: android-core ## Build the Android app's debug and release APKs into android/app/build
	$(GRADLE) assembleDebug assembleRelease

.PHONY: android-check
android-check: android-core ## Test the Android app: unit and screenshot tests, and lint
	$(GRADLE) testDebugUnitTest verifyRoborazziDebug lintDebug

.PHONY: android-screenshots
android-screenshots: android-core ## Record the Android app's screenshots anew, into android/app/screenshots
	$(GRADLE) recordRoborazziDebug

## --- packaging -----------------------------------------------------------

# `make rpm` builds an installable package from binaries this Makefile
# compiles, rather than from source inside the build root, so it needs no Go
# toolchain and no network there. Version 0 is deliberate — the project has cut
# no release — and the release field carries the commit's UTC time and hash.
# The time is what sorts: a hash alone does not, so two builds on one day would
# otherwise upgrade or not by chance.
RPMBUILD    ?= rpmbuild
RPM_NAME    ?= juist
RPMTOP      ?= $(abspath $(BUILDDIR)/rpm)
RPM_VERSION ?= 0
RPM_COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# A tree with changes, untracked files included, carries the build's time too,
# so two builds of one commit's changes still sort, one after the other.
# Expanded once, so the name of the package and its metadata agree.
ifeq ($(origin RPM_DIRTY),undefined)
RPM_DIRTY := $(shell [ -n "$$(git status --porcelain 2>/dev/null)" ] && echo .dirty$$(date -u +%Y%m%d%H%M%S))
endif
RPM_STAMP   ?= $(shell TZ=UTC git log -1 --format=%cd --date=format-local:%Y%m%d%H%M%S 2>/dev/null || \
                 date -u +%Y%m%d%H%M%S)
RPM_RELEASE ?= 0.$(RPM_STAMP)git$(RPM_COMMIT)$(RPM_DIRTY)

# juist's own; THIRD_PARTY_LICENSES holds those of what it links.
RPM_LICENSE ?= BSD-3-Clause

.PHONY: rpm
rpm: ## Build an installable RPM into build/rpm/RPMS (needs rpmbuild)
	@command -v $(RPMBUILD) >/dev/null 2>&1 || { \
		echo "$(RPMBUILD) not found. On Fedora:"; \
		echo "  sudo dnf install rpm-build systemd-rpm-macros"; \
		exit 1; }
	@rm -rf $(RPMTOP)
	@mkdir -p $(RPMTOP)/SOURCES $(RPMTOP)/SPECS $(RPMTOP)/BUILD $(RPMTOP)/RPMS
	@set -e; stage=$(RPMTOP)/stage/$(RPM_NAME)-$(RPM_VERSION); mkdir -p $$stage; \
	for c in $(CMDS); do \
		echo "==> $$c"; \
		$(GOBUILD) -o $(BUILDDIR)/$$c ./cmd/$$c; \
		cp $(BUILDDIR)/$$c $$stage/$$c; \
	done; \
	$(BUILDDIR)/juist __manpage > $$stage/juist.1; \
	$(BUILDDIR)/juistd __manpage > $$stage/juistd.8; \
	cp packaging/systemd/juistd.service packaging/systemd/juistd@.service packaging/systemd/juist-ingress.service \
		packaging/systemd/juist-ingress-ports.path packaging/systemd/juist-ingress-ports.service \
		packaging/systemd/juist-serve.service packaging/systemd/juist-serve.path README.md LICENSE THIRD_PARTY_LICENSES packaging/firewall.sh packaging/exit-node.sh \
		packaging/ingress.sh packaging/serve.sh packaging/polkit/juist.rules \
		packaging/firewalld/juist.xml packaging/firewalld/juist-relay.xml packaging/firewalld/juist-ingress.xml \
		packaging/firewalld/juist-invite.xml packaging/completions/juist.bash \
		packaging/completions/_juist packaging/completions/juist.fish $$stage/; \
	tar -czf $(RPMTOP)/SOURCES/$(RPM_NAME)-$(RPM_VERSION).tar.gz \
		-C $(RPMTOP)/stage $(RPM_NAME)-$(RPM_VERSION)
	@cp packaging/rpm/juist.sysusers $(RPMTOP)/SOURCES/
	@cp packaging/rpm/juist.spec $(RPMTOP)/SPECS/
	$(RPMBUILD) --define "_topdir $(RPMTOP)" \
		--define "ver $(RPM_VERSION)" \
		--define "rel $(RPM_RELEASE)" \
		--define "license_tag $(RPM_LICENSE)" \
		-bb $(RPMTOP)/SPECS/juist.spec
	@find $(RPMTOP)/RPMS -name '*.rpm'

# `make deb` is the same package for Debian and Ubuntu, assembled with
# dpkg-deb from binaries this Makefile compiles, so it needs neither debhelper
# nor root: --root-owner-group records root ownership without fakeroot. The
# version sorts between test builds the way RPM_RELEASE does. DEB_ARCH picks
# the target and GOARCH follows it, so `make deb DEB_ARCH=arm64` cross-builds.
DEBTOP      ?= $(abspath $(BUILDDIR)/deb)
DEB_ARCH    ?= $(shell dpkg --print-architecture 2>/dev/null || $(GO) env GOARCH)
DEB_VERSION ?= $(RPM_VERSION)~$(RPM_STAMP)git$(RPM_COMMIT)$(subst .dirty,+dirty,$(RPM_DIRTY))
DEB_GOARCH   = $(or $(DEB_GOARCH_$(DEB_ARCH)),$(error DEB_ARCH=$(DEB_ARCH) is not a target this Makefile knows))
DEB_GOARCH_amd64 = amd64
DEB_GOARCH_arm64 = arm64
DEB_GOARCH_armhf = arm
DEB_GOARCH_i386  = 386

.PHONY: deb
deb: ## Build an installable .deb for Debian and Ubuntu into build/deb (needs dpkg-deb)
	@command -v dpkg-deb >/dev/null 2>&1 || { \
		echo "dpkg-deb not found; it ships with dpkg on Debian and Ubuntu"; exit 1; }
	@rm -rf $(DEBTOP)
	@set -e; root=$(DEBTOP)/root; bin=$(call bindir,linux,$(DEB_GOARCH)); \
	for c in $(CMDS); do \
		echo "==> $$c ($(DEB_ARCH))"; \
		GOOS=linux GOARCH=$(DEB_GOARCH) $(GOBUILD) -o $$bin/$$c ./cmd/$$c; \
		install -D -m 0755 $$bin/$$c $$root/usr/bin/$$c; \
	done; \
	for u in juistd.service juistd@.service juist-ingress.service juist-serve.service; do \
		install -D -m 0644 packaging/systemd/$$u $$root/usr/lib/systemd/system/$$u; \
		sed -i 's|^ExecStart=/usr/local/bin/juistd |ExecStart=/usr/bin/juistd |' $$root/usr/lib/systemd/system/$$u; \
		grep -q '^ExecStart=/usr/bin/juistd ' $$root/usr/lib/systemd/system/$$u; \
	done; \
	for u in juist-serve.path juist-ingress-ports.path juist-ingress-ports.service; do \
		install -D -m 0644 packaging/systemd/$$u $$root/usr/lib/systemd/system/$$u; \
	done; \
	install -D -m 0644 packaging/rpm/juist.sysusers $$root/usr/lib/sysusers.d/juist.conf; \
	install -D -m 0644 README.md $$root/usr/share/doc/juist/README.md; \
	install -D -m 0644 LICENSE $$root/usr/share/doc/juist/copyright; \
	install -D -m 0644 THIRD_PARTY_LICENSES $$root/usr/share/doc/juist/THIRD_PARTY_LICENSES; \
	install -d -m 0755 $$root/usr/share/man/man1 $$root/usr/share/man/man8; \
	for m in juist.1 juistd.8; do \
		c=$${m%.*}; out=$$root/usr/share/man/man$${m#*.}/$$m; \
		if [ "$$bin" = "$(BUILDDIR)" ]; then $$bin/$$c __manpage > $$out; \
		else vcs=; $(GO) version -m $$bin/$$c | grep -q vcs= && vcs=-buildvcs=true; \
			$(GO) run $$vcs $(GOFLAGS) ./cmd/$$c __manpage > $$out; fi; \
	done; \
	gzip -9n $$root/usr/share/man/man1/juist.1 $$root/usr/share/man/man8/juistd.8; \
	install -D -m 0755 packaging/firewall.sh $$root/usr/lib/juist/firewall.sh; \
	install -D -m 0755 packaging/exit-node.sh $$root/usr/lib/juist/exit-node.sh; \
	install -D -m 0755 packaging/ingress.sh $$root/usr/lib/juist/ingress.sh; \
	install -D -m 0755 packaging/serve.sh $$root/usr/lib/juist/serve.sh; \
	install -D -m 0644 packaging/polkit/juist.rules $$root/usr/share/polkit-1/rules.d/60-juist.rules; \
	for f in juist juist-relay juist-invite juist-ingress; do \
		install -D -m 0644 packaging/firewalld/$$f.xml $$root/usr/lib/firewalld/services/$$f.xml; \
	done; \
	install -D -m 0644 packaging/ufw/juist $$root/etc/ufw/applications.d/juist; \
	install -D -m 0644 packaging/completions/juist.bash $$root/usr/share/bash-completion/completions/juist; \
	install -D -m 0644 packaging/completions/_juist $$root/usr/share/zsh/vendor-completions/_juist; \
	install -D -m 0644 packaging/completions/juist.fish $$root/usr/share/fish/vendor_completions.d/juist.fish; \
	install -d -m 0755 $$root/DEBIAN; \
	install -m 0755 packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm $$root/DEBIAN/; \
	echo /etc/ufw/applications.d/juist > $$root/DEBIAN/conffiles; \
	size=$$(du -sk --exclude=DEBIAN $$root | cut -f1); \
	sed -e 's|@VERSION@|$(DEB_VERSION)|' -e 's|@ARCH@|$(DEB_ARCH)|' -e "s|@SIZE@|$$size|" \
		packaging/deb/control.in > $$root/DEBIAN/control; \
	dpkg-deb --root-owner-group -Zxz --build $$root $(DEBTOP)/juist_$(DEB_VERSION)_$(DEB_ARCH).deb >/dev/null
	@find $(DEBTOP) -maxdepth 1 -name '*.deb'

# `make pkg-freebsd` is the FreeBSD package, written by packaging/freebsd/mkpkg
# rather than pkg-create(8), so that any system builds it, to the same bytes
# from one commit. FREEBSD_ABI picks the release and machine it installs on.
FREEBSD_ABI     ?= FreeBSD:14:amd64
FREEBSD_VERSION ?= $(RPM_VERSION).$(RPM_STAMP)$(subst .dirty,.,$(RPM_DIRTY))

.PHONY: pkg-freebsd
pkg-freebsd: ## Build the FreeBSD package into build/freebsd
	@rm -rf $(BUILDDIR)/freebsd
	@sh packaging/freebsd/pkg.sh "$(GO)" "$(abspath $(BUILDDIR))/freebsd/juist-$(FREEBSD_VERSION).pkg" \
		"$(FREEBSD_VERSION)" "$(FREEBSD_ABI)" "$(abspath $(BUILDDIR))"

# `make image` is the service member's container image, written by
# packaging/image/mkimage as docker save would, for docker or podman load:
# juistd and juist for IMAGE_ARCH and this host's CA certificates.
IMAGE_ARCH  ?= amd64
# The host's CA bundle: Debian's, Fedora's, or FreeBSD's.
IMAGE_CERTS ?= $(firstword $(wildcard /etc/ssl/certs/ca-certificates.crt \
	/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/cert.pem))

.PHONY: image
image: ## Build the service member's container image into build/image
	@mkdir -p $(BUILDDIR)/image/linux-$(IMAGE_ARCH) && rm -f $(BUILDDIR)/image/juist-*-$(IMAGE_ARCH).tar
	@for c in juist juistd; do \
		GOOS=linux GOARCH=$(IMAGE_ARCH) CGO_ENABLED=0 $(GO) build -trimpath -o $(BUILDDIR)/image/linux-$(IMAGE_ARCH)/$$c ./cmd/$$c || exit 1; \
	done
	@$(GO) run ./packaging/image/mkimage -o $(BUILDDIR)/image/juist-$(FREEBSD_VERSION)-$(IMAGE_ARCH).tar \
		-tag juist:$(FREEBSD_VERSION) -arch $(IMAGE_ARCH) -mtime $$(git log -1 --format=%ct) -certs $(IMAGE_CERTS) \
		-license LICENSE -third-party THIRD_PARTY_LICENSES \
		-juistd $(BUILDDIR)/image/linux-$(IMAGE_ARCH)/juistd -juist $(BUILDDIR)/image/linux-$(IMAGE_ARCH)/juist
	@echo $(BUILDDIR)/image/juist-$(FREEBSD_VERSION)-$(IMAGE_ARCH).tar

# `make install` builds the package this system's package manager takes and
# installs it: the .deb with apt, the RPM with dnf, FreeBSD's with pkg, with
# sudo unless make already runs as root. An upgrade keeps the state directory.
SUDO ?= sudo

.PHONY: install
install: ## Build this system's package (.deb, RPM or FreeBSD's) and install it with sudo
	@set -e; \
	sudo=$(SUDO); [ "$$(id -u)" -eq 0 ] && sudo=; \
	if command -v apt >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory deb; \
		pkg=$$(find $(DEBTOP) -maxdepth 1 -name '*.deb'); \
		echo "==> installing $$pkg"; \
		$$sudo apt install -y "$$pkg"; \
	elif command -v dnf >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory rpm; \
		pkg=$$(find $(RPMTOP)/RPMS -name '*.rpm'); \
		echo "==> installing $$pkg"; \
		$$sudo dnf install -y "$$pkg"; \
	elif [ "$$(uname)" = FreeBSD ]; then \
		abi=$$(pkg config abi); \
		$(MAKE) --no-print-directory pkg-freebsd FREEBSD_ABI=$$abi; \
		pkg=$$(find $(BUILDDIR)/freebsd -name '*.pkg'); \
		echo "==> installing $$pkg"; \
		$$sudo pkg add "$$pkg"; \
	else \
		echo "make install knows apt (Debian, Ubuntu), dnf (Fedora) and pkg (FreeBSD); use make deb, rpm or pkg-freebsd"; \
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
	$(GO) vet $(GOFLAGS) -tags interop ./interop

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

.PHONY: licenses
licenses: ## Write THIRD_PARTY_LICENSES from the modules juist links
	$(GO) run ./packaging/licenses > THIRD_PARTY_LICENSES.tmp && mv THIRD_PARTY_LICENSES.tmp THIRD_PARTY_LICENSES

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
check: lint tidy-check build-test test-race tcb repro ## Everything CI gates on; run before pushing

# `make ci` is every job .github/workflows/ci.yml runs, on this machine: what
# check gates, with the host-feature probes failing rather than skipping as on
# the runner, then the cross builds, the vulnerability scan, the packages,
# and last the privileged tests, the one step that asks for sudo.
CI_TOOLS = ip ping iptables nft rpmbuild dpkg-deb sudo

.PHONY: ci
ci: ci-deps ## Run every CI job locally (asks for sudo for the privileged tests)
	JUIST_REQUIRE_HOST_NET=1 $(MAKE) --no-print-directory check
	$(MAKE) --no-print-directory cross govulncheck rpm deb pkg-freebsd
	$(MAKE) --no-print-directory test-os-plumbing-sudo
	@echo "ci: every job passed"

# `make ci-vm` is CI without a hosted runner: make ci and make interop in a
# Fedora VM under KVM, which ci/main.go sets up in ~/.cache/juist-ci on first
# use, from the working tree as it is. It logs to build/ci.
.PHONY: ci-vm
ci-vm: ## Run every CI job in a KVM VM it sets up itself (needs qemu, ssh); logs to build/ci
	$(GO) run ./ci $(if $(CI_MAKE),-make "$(CI_MAKE)")

.PHONY: ci-deps
ci-deps: ## Check the tools make ci needs, and say how to install them
	@missing=""; \
	for t in $(CI_TOOLS); do command -v $$t >/dev/null 2>&1 || missing="$$missing $$t"; done; \
	[ -c /dev/net/tun ] || missing="$$missing /dev/net/tun"; \
	if [ -n "$$missing" ]; then \
		echo "ci: missing:$$missing"; \
		echo "hint: on Fedora: sudo dnf install iproute iputils iptables-nft rpm-build systemd-rpm-macros dpkg"; \
		exit 1; \
	fi

.PHONY: clean
clean: ## Remove build and test artifacts
	rm -rf $(BUILDDIR)
	rm -f $(COVERPROFILE)
	$(GO) clean -testcache

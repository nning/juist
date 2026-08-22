package log

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The trusted computing base: the packages docs/06-verification.md scopes the
// external audit to. Everything else in the tree is glue around production-
// tested imports and can be wrong without membership being wrong.
var tcbPackages = []string{
	"github.com/nning/wg-p2p/types",
	"github.com/nning/wg-p2p/trust/log",
	"github.com/nning/wg-p2p/trust/secrets",
	"github.com/nning/wg-p2p/trust/store",
}

// Third-party modules the TCB is allowed to depend on, and why.
//
// The list is short on purpose. docs/03-control-plane-options.md rejected
// go-libp2p partly on TCB size — "a large framework in the audit path, against
// boring auditable Go" — and that argument only holds if the TCB's dependency
// closure stays something a reviewer can actually read.
var allowedModules = map[string]string{
	// The Ed25519 group implementation from the standard library, repackaged
	// as an importable module. Needed to reject small-order public keys, which
	// crypto/ed25519 gives no way to detect.
	"filippo.io/edwards25519": "small-order public key rejection",

	// The CBOR codec, in CTAP2 canonical mode, and its float16 helper. Same
	// library and same mode tka uses.
	"github.com/fxamacker/cbor/v2": "canonical record encoding",
	"github.com/x448/float16":      "transitive dependency of the CBOR codec",
}

// Standard-library packages the TCB must not reach even transitively, with the
// property each exclusion protects. These are absolute: nothing in the audit
// scope may pull them in through any path.
var forbiddenAnywhere = map[string]string{
	"net":      "the trust layer must not speak to the network: records carry their own proof, so the transports that move them are untrusted and live outside it",
	"net/http": "as above",
	"os/exec":  "nothing in the trust layer runs a program",
	"plugin":   "nothing in the trust layer loads code",
}

// Packages the TCB must not import *directly*, per package. Transitive reach
// is the wrong granularity here — os and time arrive through half the standard
// library — so what is checked is what the code itself asks for.
//
// The clock and the filesystem are excluded from the packages that decide
// validity, because a record's verdict has to be a function of the record and
// the state it is applied to. If it could depend on the time or on a file, two
// nodes holding the same log could disagree about who is a member.
var forbiddenDirect = map[string][]string{
	"github.com/nning/wg-p2p/types":         {"os", "time", "math/rand", "math/rand/v2"},
	"github.com/nning/wg-p2p/trust/log":     {"os", "time", "math/rand", "math/rand/v2"},
	"github.com/nning/wg-p2p/trust/secrets": {"os", "time", "math/rand", "math/rand/v2"},
	// trust/store is the one that owns files, so os is its job; the clock and
	// weak randomness still are not.
	"github.com/nning/wg-p2p/trust/store": {"time", "math/rand", "math/rand/v2"},
}

// TestTCBDependencies is the architectural invariant behind the audit scope in
// docs/06-verification.md, enforced rather than asserted. It lives here
// because trust/log is the package that scope centres on.
//
// A dependency added to the TCB is a dependency an auditor has to read, so
// adding one is a decision to make deliberately: extend the allowlist, with
// the reason, in the same commit.
func TestTCBDependencies(t *testing.T) {
	for _, pkg := range tcbPackages {
		for _, dep := range goList(t, "-deps", pkg) {
			if why, bad := forbiddenAnywhere[dep]; bad {
				t.Errorf("%s reaches %q: %s", pkg, dep, why)
			}
			if !isThirdParty(dep) {
				continue
			}
			if !slices.ContainsFunc(modulePrefixes(), func(m string) bool {
				return dep == m || strings.HasPrefix(dep, m+"/")
			}) {
				t.Errorf("%s reaches third-party package %q, which is not in the TCB allowlist; "+
					"add it with a reason or keep it out of the trust layer", pkg, dep)
			}
		}
		direct := goList(t, "-f", "{{join .Imports \"\\n\"}}", pkg)
		for _, excluded := range forbiddenDirect[pkg] {
			if slices.Contains(direct, excluded) {
				t.Errorf("%s imports %q directly, which this package must not", pkg, excluded)
			}
		}
	}
}

// TestTCBHasNoTailscaleDependency keeps the layering in
// docs/04-architecture.md honest from the other direction: the connectivity
// layer is built on Tailscale's stack, and the trust layer must not be. A
// vendored-engine upgrade must never be able to change who is a member.
func TestTCBHasNoTailscaleDependency(t *testing.T) {
	for _, pkg := range tcbPackages {
		for _, dep := range goList(t, "-deps", pkg) {
			if strings.HasPrefix(dep, "tailscale.com") ||
				strings.HasPrefix(dep, "github.com/tailscale/") {
				t.Errorf("%s reaches %q; the trust layer must not depend on the connectivity stack", pkg, dep)
			}
		}
	}
}

func modulePrefixes() []string {
	out := make([]string, 0, len(allowedModules)+1)
	out = append(out, "github.com/nning/wg-p2p")
	for m := range allowedModules {
		out = append(out, m)
	}
	return out
}

// isThirdParty reports whether an import path is outside the standard library.
// Standard-library paths have no dot in their first element.
func isThirdParty(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return strings.Contains(first, ".")
}

// goList runs go list and returns its non-empty output lines.
//
// Shelling out to the toolchain is the only way to resolve a module-aware
// import graph from a test without adding golang.org/x/tools to the tree,
// which for a test that exists to keep dependencies out would be
// self-defeating.
func goList(t *testing.T, args ...string) []string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool available to resolve the import graph")
	}
	out, err := exec.Command("go", append([]string{"list"}, args...)...).Output()
	if err != nil {
		t.Fatalf("go list %v: %v", args, err)
	}
	var deps []string
	for line := range strings.Lines(string(out)) {
		if line = strings.TrimSpace(line); line != "" {
			deps = append(deps, line)
		}
	}
	return deps
}

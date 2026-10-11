package log

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The trusted computing base's core: the packages audit-scope places core.
// Everything else can be wrong without membership being wrong.
var tcbPackages = []string{
	"github.com/nning/juist/types",
	"github.com/nning/juist/trust/log",
	"github.com/nning/juist/trust/secrets",
	"github.com/nning/juist/trust/store",
	"github.com/nning/juist/trust/enroll",
}

// Third-party modules the TCB is allowed to depend on. Short on purpose: the
// audit scope only means something if its dependency closure stays readable.
var allowedModules = map[string]string{
	// The Ed25519 group implementation from the standard library, repackaged
	// as an importable module. Needed to reject small-order public keys, which
	// crypto/ed25519 gives no way to detect, and for the group arithmetic
	// SPAKE2 needs at enrollment, which crypto/ecdh does not expose.
	"filippo.io/edwards25519": "small-order public key rejection; the SPAKE2 group",

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

// Packages the TCB must not import directly, per package; transitive reach is
// the wrong granularity, since os and time arrive through half the standard
// library. The clock and the filesystem are excluded from the packages that
// decide validity: a verdict must be a function of the record and the state.
var forbiddenDirect = map[string][]string{
	"github.com/nning/juist/types":         {"os", "time", "math/rand", "math/rand/v2"},
	"github.com/nning/juist/trust/log":     {"os", "time", "math/rand", "math/rand/v2"},
	"github.com/nning/juist/trust/secrets": {"os", "time", "math/rand", "math/rand/v2"},
	// The enrollment protocol runs over a connection its caller owns, so the
	// caller dials, listens and keeps time.
	"github.com/nning/juist/trust/enroll": {"os", "time", "math/rand", "math/rand/v2"},
	// trust/store is the one that owns files, so os is its job; the clock and
	// weak randomness still are not.
	"github.com/nning/juist/trust/store": {"time", "math/rand", "math/rand/v2"},
}

// TestTCBDependencies enforces the audit scope in docs/06-verification.md. A
// dependency added to the TCB is one an auditor has to read: extend the
// allowlist, with the reason, in the same commit.
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

// TestTCBHasNoTailscaleDependency: the connectivity layer is built on
// Tailscale's stack and the trust layer must not be, so no engine upgrade can
// change who is a member.
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
	out = append(out, "github.com/nning/juist")
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

// goList runs go list and returns its non-empty output lines. Shelling out
// resolves a module-aware import graph without adding golang.org/x/tools,
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

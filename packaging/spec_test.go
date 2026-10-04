package packaging

import (
	"os"
	"path"
	"strings"
	"testing"
)

// The RPM owns every directory of juist's own it installs into, so that
// removing it leaves none behind.
func TestTheRPMOwnsItsDirectories(t *testing.T) {
	b, err := os.ReadFile("rpm/juist.spec")
	if err != nil {
		t.Fatal(err)
	}
	_, files, ok := strings.Cut(string(b), "\n%files\n")
	if !ok {
		t.Fatal("the spec lists no files")
	}
	owned := map[string]bool{}
	var paths []string
	for line := range strings.SplitSeq(files, "\n") {
		if strings.HasPrefix(line, "%changelog") {
			break
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || fields[0] == "%doc" {
			continue
		}
		p := fields[len(fields)-1]
		if strings.Contains(line, "%dir ") {
			owned[p] = true
		}
		paths = append(paths, p)
	}
	for _, p := range paths {
		for d := path.Dir(p); d != "." && d != "/"; d = path.Dir(d) {
			if base := path.Base(d); (base == "juist" || base == "%{name}") && !owned[d] {
				t.Errorf("%s is installed into %s, which the package does not own", p, d)
			}
		}
	}
}

// Both packages bring polkit, which runs their rule for juistd's DNS, where
// the host takes recommendations.
func TestThePackagesRecommendPolkit(t *testing.T) {
	for file, want := range map[string]string{"rpm/juist.spec": "\nRecommends:     polkit\n",
		"deb/control.in": "\nRecommends: polkitd\n"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s does not recommend polkit", file)
		}
	}
}

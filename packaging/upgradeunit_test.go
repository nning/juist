package packaging

import (
	"os"
	"strings"
	"testing"
)

// The upgrade timer's instance is a network's name as juist status shows it,
// such as amber-falcon, which %I would unescape to amber/falcon.
func TestTheUpgradeUnitPassesTheNetworkAsNamed(t *testing.T) {
	for _, unit := range []string{"systemd/juist-upgrade@.service", "systemd/juist-upgrade@.timer"} {
		b, err := os.ReadFile(unit)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "%I") {
			t.Errorf("%s names the network by %%I, which turns its - into /", unit)
		}
	}
	b, _ := os.ReadFile("systemd/juist-upgrade@.service")
	if !strings.Contains(string(b), "--when-ready %i\n") {
		t.Error("juist-upgrade@.service does not pass the instance as it is")
	}
}

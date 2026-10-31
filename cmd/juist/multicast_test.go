package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// The status says whether the device carries multicast and which groups it
// routes, and nothing where it has no device to.
func TestStatusSaysMulticast(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, Device: "juist0", Derived: ipc.Derived{NetworkName: "home", Members: 2, Peers: 1}}
	for _, c := range []struct {
		m    *ipc.Multicast
		want string
	}{
		{&ipc.Multicast{}, "on"},
		{&ipc.Multicast{Off: true, Groups: []string{"224.0.0.251"}}, "off"},
		{&ipc.Multicast{Groups: []string{"224.0.0.251", "239.255.255.250"}}, "on, routed: 224.0.0.251, 239.255.255.250"},
	} {
		st.Multicast = c.m
		head := statusOf(st, testNow(), noPaint).head
		if !slices.Contains(head, line{kind: lineField, label: "Multicast", text: c.want}) {
			t.Errorf("with %+v the status says\n%+v", c.m, head)
		}
	}
	st.Multicast = nil
	if head := statusOf(st, testNow(), noPaint).head; slices.ContainsFunc(head, func(l line) bool { return l.label == "Multicast" }) {
		t.Errorf("without a device the status says\n%+v", head)
	}
}

func files(m map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if v, ok := m[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
}

// Health warns where avahi runs and leaves the device out, as it does a
// point-to-point one by default, and says what lets it in.
func TestHealthWarnsOfAvahiLeavingTheDeviceOut(t *testing.T) {
	t.Parallel()
	const conf, pid = "/etc/avahi/avahi-daemon.conf", "/run/avahi-daemon/pid"
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"not running", map[string]string{conf: "[server]\n"}, ""},
		{"by default", map[string]string{pid: "1\n", conf: "[server]\nuse-ipv4=yes\n"}, "allow-point-to-point=yes under [server]"},
		{"without a configuration", map[string]string{pid: "1\n"}, "allow-point-to-point=yes under [server]"},
		{"allowed", map[string]string{pid: "1\n", conf: "[server]\nallow-point-to-point=yes\n"}, ""},
		{"allowed as true", map[string]string{pid: "1\n", conf: "[server]\nallow-point-to-point=True\n"}, ""},
		{"not allowed as no", map[string]string{pid: "1\n", conf: "[server]\nallow-point-to-point=no\n"}, "allow-point-to-point=yes under [server]"},
		{"allowed elsewhere", map[string]string{pid: "1\n", conf: "[publish]\nallow-point-to-point=yes\n"}, "allow-point-to-point=yes under [server]"},
		{"denied", map[string]string{pid: "1\n", conf: "[server]\nallow-point-to-point=yes\ndeny-interfaces=juist0\n"}, "name juist0 in allow-interfaces"},
		{"not allowed", map[string]string{pid: "1\n", conf: "[server]\nallow-point-to-point=yes\nallow-interfaces=eth0, wlan0\n"}, "name juist0 in allow-interfaces"},
		{"allowed by name", map[string]string{pid: "1\n", conf: "[server]\nallow-point-to-point=yes\nallow-interfaces=eth0, juist0\n"}, ""},
	} {
		got := render(avahiNotes(files(c.files), "juist0"))
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: health says\n%s", c.name, got)
		}
	}
}

func TestGroupsAreIPv4MulticastAlone(t *testing.T) {
	t.Parallel()
	got, err := parseGroups(" 239.255.255.250,224.0.0.251,,239.255.255.250 ")
	if err != nil || !slices.Equal(got, []string{"239.255.255.250", "224.0.0.251"}) {
		t.Errorf("parsed %v, %v", got, err)
	}
	if got, err := parseGroups(""); err != nil || got == nil || len(got) != 0 {
		t.Errorf("none parsed as %#v, %v", got, err)
	}
	for _, bad := range []string{"10.0.0.1", "ff02::fb", "mdns"} {
		if _, err := parseGroups(bad); err == nil {
			t.Errorf("%s was taken", bad)
		}
	}
	var many []string
	for i := range ipc.MaxGroups + 1 {
		many = append(many, fmt.Sprintf("239.1.1.%d", i+1))
	}
	if _, err := parseGroups(strings.Join(many, ",")); err == nil {
		t.Error("too many groups were taken")
	}
}

// A policy passing multicast on a network at schema 21 is refused with the
// upgrade it needs.
func TestAMulticastPolicyAsksForTheUpgrade(t *testing.T) {
	t.Parallel()
	p := &types.Policy{Rules: []types.PolicyRule{{Multicast: true, From: types.PolicyRefs{Any: true}, To: types.PolicyRefs{Any: true}}}}
	if err := multicastSchema(p, 21); err == nil || !strings.Contains(err.Error(), "juist log upgrade") {
		t.Errorf("at schema 21: %v", err)
	}
	if err := multicastSchema(p, types.SchemaMulticast); err != nil {
		t.Errorf("at schema 22: %v", err)
	}
	if err := multicastSchema(&types.Policy{Rules: []types.PolicyRule{{From: types.PolicyRefs{Any: true}, To: types.PolicyRefs{Any: true}}}}, 21); err != nil {
		t.Errorf("a policy without multicast at schema 21: %v", err)
	}
}

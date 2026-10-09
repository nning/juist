package mobile

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// fakePlatform seals by reversing and prefixing, which is enough to tell a
// sealed file from a plain one, and logs to the test.
type fakePlatform struct {
	t  *testing.T
	mu sync.Mutex
	// opened counts what was opened.
	opened int
}

func (p *fakePlatform) Protect(int32) bool              { return true }
func (p *fakePlatform) Establish(string) (int32, error) { return -1, errors.New("no VPN in tests") }
func (p *fakePlatform) Interfaces() (string, error)     { return `[]`, nil }
func (p *fakePlatform) Log(line string)                 { p.t.Log(line) }
func (p *fakePlatform) Seal(plain []byte) ([]byte, error) {
	return append([]byte("sealed:"), rev(plain)...), nil
}
func (p *fakePlatform) Open(sealed []byte) ([]byte, error) {
	rest, ok := bytes.CutPrefix(sealed, []byte("sealed:"))
	if !ok {
		return nil, errors.New("not sealed here")
	}
	p.mu.Lock()
	p.opened++
	p.mu.Unlock()
	return rev(rest), nil
}

func rev(b []byte) []byte {
	out := slices.Clone(b)
	slices.Reverse(out)
	return out
}

func statusOf(t *testing.T, c *Core) view {
	t.Helper()
	s, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	var v view
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestACoreKeepsItsKeysSealedAcrossRestarts(t *testing.T) {
	t.Cleanup(func() { keys.SealWith(nil) })
	home := filepath.Join(t.TempDir(), "juist")
	p := &fakePlatform{t: t}
	c, err := Start(home, p)
	if err != nil {
		t.Fatal(err)
	}
	v := statusOf(t, c)
	c.Close()
	if v.State != "none" || !strings.HasPrefix(v.Self.Identity, "nid:") {
		t.Errorf("a fresh core: %+v", v)
	}
	raw, err := os.ReadFile(filepath.Join(home, keys.NodeKeysFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(keys.IdentityTag)) || !bytes.Contains(raw, []byte(keys.SealedTag)) {
		t.Fatalf("the device's keys on disk:\n%s", raw)
	}

	c, err = Start(home, p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if second, err := Start(t.TempDir(), &fakePlatform{t: t}); err == nil {
		second.Close()
		t.Error("a second core started beside the first, and took its hooks")
	}
	if again := statusOf(t, c); again.Self.Identity != v.Self.Identity || p.opened == 0 {
		t.Errorf("restarted as %s, opened %d times; was %s", again.Self.Identity, p.opened, v.Self.Identity)
	}
	if _, err := c.Ping(v.Self.Identity); err == nil {
		t.Error("pinged outside any network")
	}
	if err := c.Join("7-nonsense", "phone", nil); err == nil {
		t.Error("joined by a code of words no code holds")
	}
}

func TestCompleteWordOffersTheWordsOfItsPlace(t *testing.T) {
	// drumbeat is a two-syllable word, which only even places hold.
	if got := CompleteWord("Drum", 0); got != "drumbeat" {
		t.Errorf("completing drum at 0: %q", got)
	}
	if got := CompleteWord("drum", 1); got != "" {
		t.Errorf("completing drum at 1: %q", got)
	}
	if got := CompleteWord("Adroitness", 1); got != "adroitness" {
		t.Errorf("completing a whole word: %q", got)
	}
	if got := strings.Split(CompleteWord("a", 1), "\n"); len(got) != maxCompletions {
		t.Errorf("completing a at 1: %d words, want %d", len(got), maxCompletions)
	}
	for _, pos := range []int{-1, 3} {
		if got := CompleteWord("a", pos); got != "" {
			t.Errorf("completing at %d: %q", pos, got)
		}
	}
}

func TestCheckInviteSaysWhatIsWrong(t *testing.T) {
	if msg := CheckInvite("42-drumbeat-tolerance-glucose"); msg != "" {
		t.Errorf("a valid code: %s", msg)
	}
	if msg := CheckInvite("42-tolerance-drumbeat-glucose"); !strings.Contains(msg, "wrong place") {
		t.Errorf("two words swapped: %q", msg)
	}
}

func TestInterfacesAreReadAsAndroidListsThem(t *testing.T) {
	list, err := parseInterfaces(`[{"name":"wlan0","index":30,"mtu":1500,"up":true,"multicast":true,
		"addrs":["192.168.1.5/24","fe80::1/64","nonsense"]},{"name":"lo","index":1,"up":true,"loopback":true}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || !list[0].IsUp() || list[0].Index != 30 || !list[1].IsLoopback() {
		t.Fatalf("interfaces: %+v", list)
	}
	addrs, _ := list[0].Addrs()
	if len(addrs) != 2 || addrs[0].String() != "192.168.1.5/24" || addrs[1].String() != "fe80::1/64" {
		t.Errorf("wlan0's addresses: %v", addrs)
	}
}

func identity(b byte) types.Identity {
	var id types.Identity
	id[0] = b
	return id
}

// sampleStatus is a device in a network of five: one member reached
// directly, one through a relay, one being looked for, one not heard from.
func sampleStatus() *ipc.Status {
	self, a, b, c, d := identity(1), identity(2), identity(3), identity(4), identity(5)
	return &ipc.Status{Self: self, InNetwork: true,
		Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32"), netip.MustParsePrefix("fd00::5/128")},
		Derived: ipc.Derived{NetworkName: "home", SelfName: "phone", Members: 5, Peers: 3, Unreachable: 1,
			Silent: []string{"dora"}, LeaseSigners: 1, Vouchers: 1, Vouching: 1, FreshSince: 100, FreshUntil: 200,
			RelayCapable: 1,
			Devices: []ipc.Device{
				{Identity: self, Name: "phone", V4: "10.0.0.5"},
				{Identity: c, Name: "cleo"}, {Identity: a, Name: "anna", Roles: []types.Role{"admin"}},
				{Identity: b, Name: "bert"}, {Identity: d, Name: "dora"},
			}},
		Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 2, TunnelsDown: []string{"cleo"}, ReachChecked: 150,
			Seeking: []string{"cleo"},
			Reach: []ipc.PeerReach{{Identity: a, Live: true, Direct: true}, {Identity: b, Live: true},
				{Identity: c, Seeking: true, Since: 140}}},
	}
}

func TestTheViewOffersTheExitNodes(t *testing.T) {
	s := sampleStatus()
	if v := viewOf(s); v.Exit != nil {
		t.Errorf("an exit node offered where none is: %+v", v.Exit)
	}
	anna := s.Devices[2].Identity
	s.Exit = &ipc.Exit{Offering: []types.Identity{anna}}
	v := viewOf(s)
	if v.Exit == nil || len(v.Exit.Offering) != 1 || v.Exit.Offering[0].Name != "anna" || v.Exit.Node != "" {
		t.Fatalf("exit nodes on offer: %+v", v.Exit)
	}
	s.Exit = &ipc.Exit{Node: anna, Name: "anna", Refused: "the exit node does not answer"}
	if v := viewOf(s); v.Exit == nil || v.Exit.Name != "anna" || v.Exit.Refused == "" {
		t.Errorf("an exit node chosen and refused: %+v", v.Exit)
	}
}

func TestTheViewJudgesAsJuistStatusDoes(t *testing.T) {
	s := sampleStatus()
	v := viewOf(s)
	if v.State != "connected" || v.Self.Name != "phone" || v.Self.V4 != "10.0.0.5" || v.Self.V6 != "fd00::5" ||
		v.Fresh.State != "fresh" {
		t.Errorf("view: %+v", v)
	}
	var got []string
	for _, m := range v.Members {
		got = append(got, m.Name+":"+m.Reach)
	}
	if want := []string{"anna:direct", "bert:relay", "cleo:sought", "dora:silent"}; !slices.Equal(got, want) {
		t.Errorf("members %v, want %v", got, want)
	}
	if v.Tunnels != (tunnels{Live: 2, Total: 3, Checked: 150}) {
		t.Errorf("tunnels %+v", v.Tunnels)
	}
	var kinds []string
	for _, a := range v.Alarms {
		kinds = append(kinds, a.Kind)
	}
	if want := []string{"silent", "seeking"}; !slices.Equal(kinds, want) {
		t.Errorf("alarms %v, want %v", kinds, want)
	}

	s.Stale, s.Alarm = true, "two heads"
	if v := viewOf(s); v.State != "disconnected" || v.Fresh.State != "stale" || v.Alarms[0].Kind != "fork" {
		t.Errorf("with a fork alarm: %+v", v)
	}
	s.Alarm = ""
	if v := viewOf(s); v.State != "limited" {
		t.Errorf("stale: %s", v.State)
	}
	s.NotMember = true
	if v := viewOf(s); v.State != "removed" {
		t.Errorf("removed: %s", v.State)
	}
	s.Disabled, s.StartError = "IY5WHNAM5UBB", "the mesh did not start"
	if v := viewOf(s); v.State != "disabled" {
		t.Errorf("disabled: %s", v.State)
	}
}

// The app reads what viewOf writes; android/app's unit tests read this file
// too, so the two sides cannot drift apart unnoticed. JUIST_UPDATE_GOLDEN=1
// writes it anew.
func TestTheViewIsWhatTheAppReads(t *testing.T) {
	s := sampleStatus()
	s.EpochError = "no wrap for this device"
	got, err := json.MarshalIndent(viewOf(s), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "view.json")
	if os.Getenv("JUIST_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the view is now\n%s\nnot %s; if the app reads it, JUIST_UPDATE_GOLDEN=1 and update android/app too", got, path)
	}
}

// recordingPlatform keeps what the core establishes the VPN with.
type recordingPlatform struct {
	fakePlatform
	established []string
}

func (p *recordingPlatform) Establish(config string) (int32, error) {
	p.established = append(p.established, config)
	return -1, nil
}

// The app brings the VPN up with what Establish hands it, through an exit
// node its routes and DNS too; android/app's unit tests read this file, so
// that a field the app no longer finds, as the DNS servers, fails a test
// rather than leaking lookups past the tunnel. JUIST_UPDATE_GOLDEN=1 writes
// it anew.
func TestTheVPNConfigIsWhatTheAppReads(t *testing.T) {
	p := &recordingPlatform{fakePlatform: fakePlatform{t: t}}
	_, err := vpn{p: p}.Establish(conn.VPNConfig{
		Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.7/32"), netip.MustParsePrefix("fd00:1:2::7/128")},
		Routes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd00:1:2::/48"),
			netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/2"), netip.MustParsePrefix("2000::/3")},
		DNS: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd00:1:2::1")},
		MTU: 1280,
	})
	if err == nil || len(p.established) != 1 {
		t.Fatalf("established %q, %v", p.established, err)
	}
	got := []byte(p.established[0] + "\n")
	path := filepath.Join("testdata", "establish.json")
	if os.Getenv("JUIST_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the VPN's config is now\n%s\nnot %s; if the app reads it, JUIST_UPDATE_GOLDEN=1 and update android/app too", got, path)
	}
}

func TestTheViewWarnsBeforeFreshnessEnds(t *testing.T) {
	s := sampleStatus()
	now := time.Now().Unix()
	s.FreshSince, s.FreshUntil = now-30*3600, now+18*3600
	v := viewOf(s)
	i := slices.IndexFunc(v.Alarms, func(a alarm) bool { return a.Kind == "freshnessEnding" })
	if i < 0 || v.Alarms[i].Count != 18 {
		t.Fatalf("alarms %+v, want freshnessEnding in 18 hours", v.Alarms)
	}
}

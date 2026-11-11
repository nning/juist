package mobile

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// vpnPlatform establishes a datagram socket pair per call, as a VpnService
// hands its descriptor over, and keeps what each was established with.
type vpnPlatform struct {
	fakePlatform
	vmu   sync.Mutex
	given []establish
	far   []int
}

func (p *vpnPlatform) Establish(config string) (int32, error) {
	var e establish
	if err := json.Unmarshal([]byte(config), &e); err != nil {
		return -1, err
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	p.vmu.Lock()
	defer p.vmu.Unlock()
	p.given = append(p.given, e)
	p.far = append(p.far, fds[1])
	return int32(fds[0]), nil
}

func (p *vpnPlatform) last() establish {
	p.vmu.Lock()
	defer p.vmu.Unlock()
	if len(p.given) == 0 {
		return establish{}
	}
	return p.given[len(p.given)-1]
}

func (p *vpnPlatform) close() {
	p.vmu.Lock()
	defer p.vmu.Unlock()
	for _, fd := range p.far {
		unix.Close(fd)
	}
}

// create founds a network named name with this slot's device alone in it, an
// admin of its own signing, numbering from v4.
func create(t *testing.T, n *network, name string, v4 netip.Prefix) { createIn(t, name, v4, n) }

// createIn founds one network with every one of ns's devices in it, and
// hands it to each.
func createIn(t *testing.T, name string, v4 netip.Prefix, ns ...*network) {
	t.Helper()
	createWith(t, name, v4, nil, ns...)
}

// createWith is createIn with others, devices of no core here, as members too.
func createWith(t *testing.T, name string, v4 netip.Prefix, others []types.NodeRecord, ns ...*network) {
	t.Helper()
	admin, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var recs []types.NodeRecord
	addr := v4.Addr()
	for i, n := range ns {
		resp, err := n.call(ipc.Request{Command: ipc.CmdSelf})
		if err != nil {
			t.Fatal(err)
		}
		self := resp.Self
		addr = addr.Next()
		a := addr
		recs = append(recs, types.NodeRecord{Identity: self.Identity, Name: fmt.Sprintf("phone%d", i), WireGuard: self.Keys.WireGuard,
			X25519: self.Keys.X25519, MLKEM: self.Keys.MLKEM, Signing: self.Signing, V4: &a})
	}
	for _, o := range others {
		addr = addr.Next()
		a := addr
		o.V4 = &a
		recs = append(recs, o)
	}
	var disable [32]byte
	sealer := func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		_, r, err := secrets.NewEpoch(epoch, members)
		return r, err
	}
	g, err := log.Genesis(name, 1,
		[]types.AdminKey{{Public: admin.Public(), Signing: new(admin.SigningKey()), Endorsement: admin.Endorsement(), Votes: 1, Name: "admin"}},
		[]types.Hash{types.DisablementCommit(disable[:])}, recs, sealer)
	if err != nil {
		t.Fatal(err)
	}
	g.State.V4Prefix = &v4
	if err := g.Sign(admin); err != nil {
		t.Fatal(err)
	}
	body, err := g.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range ns {
		if _, err := n.call(ipc.Request{Command: ipc.CmdCreate, Records: [][]byte{body}}); err != nil {
			t.Fatal(err)
		}
	}
}

// gossipOnLoopback has every slot's mesh take log sync on the loopback,
// since no device here carries the overlay's addresses.
func gossipOnLoopback(t *testing.T) {
	meshForTests = func(_ int, o *daemon.Options) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Error(err)
			return
		}
		o.GossipListener = ln
		o.DisableDiscovery, o.DisableDHT = true, true
	}
	t.Cleanup(func() { meshForTests = nil })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("%s: timed out", what)
}

// v4s counts the IPv4 addresses e brings up.
func v4s(e establish) int {
	n := 0
	for _, a := range e.Addrs {
		if netip.MustParsePrefix(a).Addr().Is4() {
			n++
		}
	}
	return n
}

func routed(e establish, p netip.Prefix) bool { return slices.Contains(e.Routes, p.String()) }

func query(name string) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	return q
}

// Two networks run in one core behind one VPN device: each in a slot of its
// own, both routed, each one's names answered by the other's resolver, and
// one left without the other going down.
func TestACoreRunsTwoNetworksBehindOneVPN(t *testing.T) {
	t.Cleanup(func() { keys.SealWith(nil) })
	gossipOnLoopback(t)
	home := filepath.Join(t.TempDir(), "juist")
	p := &vpnPlatform{fakePlatform: fakePlatform{t: t}}
	defer p.close()
	c, err := Start(home, p)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			c.Close()
		}
	}()
	v4a, v4b := netip.MustParsePrefix("198.18.4.0/22"), netip.MustParsePrefix("198.18.8.0/22")
	create(t, c.network(0), "home", v4a)
	second, made, err := c.freeSlot()
	if err != nil || !made || second.slot != 1 {
		t.Fatalf("a slot for a second network: %+v, %v, %v", second, made, err)
	}
	create(t, second, "office", v4b)

	var ula [2]netip.Prefix
	waitFor(t, "both networks routed", func() bool {
		vs := statusesOf(t, c)
		if len(vs) != 2 || vs[0].Network != "home" || vs[1].Network != "office" {
			return false
		}
		for i := range 2 {
			st := c.network(i).s.Status()
			ula[i] = types.ULA(st.Network)
		}
		e := p.last()
		return routed(e, v4a) && routed(e, v4b) && routed(e, ula[0]) && routed(e, ula[1]) && v4s(e) == 2
	})
	if e := p.last(); len(e.DNS) != 1 || !netip.MustParseAddr(e.DNS[0]).Is6() || !ula[0].Contains(netip.MustParseAddr(e.DNS[0])) ||
		!slices.Equal(e.Search, []string{"home.juist", "office.juist"}) {
		t.Errorf("DNS %v searching %v, want the first network's resolver searching both", e.DNS, e.Search)
	}
	st1 := c.network(1).s.Status()
	if st1.HostConflict != nil {
		t.Errorf("networks apart in IPv4 conflicted: %+v", st1.HostConflict)
	}
	if fileExists(filepath.Join(filepath.Dir(home), "juist1", keys.NodeKeysFile)) == false {
		t.Error("the second network's keys are not beside the first's")
	}

	// Each network's resolver answers the other's names.
	waitFor(t, "the office's names answered by the home's resolver", func() bool {
		st := c.network(1).s.Status()
		if st.Names == nil || st.Names.Domain == "" {
			return false
		}
		return c.network(0).otherNames(query("phone."+st.Names.Domain)) != nil
	})
	if c.network(0).otherNames(query("example.org")) != nil {
		t.Error("another network answered a public name")
	}

	// A restart finds both again.
	c.Close()
	closed = true
	c, err = Start(home, p)
	if err != nil {
		t.Fatal(err)
	}
	closed = false
	if vs := statusesOf(t, c); len(vs) != 2 || vs[1].Network != "office" || vs[1].Slot != 1 {
		t.Fatalf("after a restart: %+v", vs)
	}

	// Leaving one keeps the other.
	before := statusesOf(t, c)[0].Self.Identity
	if err := c.Leave(1); err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(filepath.Dir(home), "juist1")) {
		t.Error("the network left kept its state")
	}
	vs := statusesOf(t, c)
	if len(vs) != 1 || vs[0].Network != "home" || vs[0].Self.Identity != before || vs[0].State == "none" {
		t.Fatalf("after leaving the office: %+v", vs)
	}
	waitFor(t, "the office's routes gone", func() bool {
		e := p.last()
		return !routed(e, v4b) && !routed(e, ula[1]) && routed(e, v4a) && routed(e, ula[0])
	})
}

// A network whose IPv4 a lower slot's holds runs without IPv4, and says so.
func TestASecondNetworkInTheFirstsIPv4RunsWithoutIt(t *testing.T) {
	t.Cleanup(func() { keys.SealWith(nil) })
	gossipOnLoopback(t)
	home := filepath.Join(t.TempDir(), "juist")
	p := &vpnPlatform{fakePlatform: fakePlatform{t: t}}
	defer p.close()
	c, err := Start(home, p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v4 := netip.MustParsePrefix("198.18.4.0/22")
	create(t, c.network(0), "home", v4)
	second, _, err := c.freeSlot()
	if err != nil {
		t.Fatal(err)
	}
	create(t, second, "office", v4)
	waitFor(t, "the office without IPv4", func() bool {
		vs := statusesOf(t, c)
		return len(vs) == 2 && slices.ContainsFunc(vs[1].Alarms, func(a alarm) bool { return a.Kind == "noV4" && slices.Equal(a.Names, []string{"home"}) }) &&
			vs[1].Self.V4 == "" && vs[0].Self.V4 != ""
	})
	ula := types.ULA(c.network(1).s.Status().Network)
	waitFor(t, "the office's IPv6 alone routed", func() bool {
		e := p.last()
		return routed(e, v4) && routed(e, ula) && v4s(e) == 1
	})
}

// A slot's state left behind by a join the app did not finish is cleared at
// the next start, and a slot never holds what is no juist home.
func TestACoreClearsWhatAnUnfinishedJoinLeft(t *testing.T) {
	t.Cleanup(func() { keys.SealWith(nil) })
	dir := t.TempDir()
	home := filepath.Join(dir, "juist")
	left := filepath.Join(dir, "juist1")
	if err := os.MkdirAll(left, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(left, keys.NodeKeysFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "juist2")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "photo.jpg"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Start(home, &fakePlatform{t: t})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if fileExists(left) {
		t.Error("a join's leftovers were kept")
	}
	if !fileExists(filepath.Join(foreign, "photo.jpg")) {
		t.Error("a directory that is no juist home was deleted")
	}
	if vs := statusesOf(t, c); len(vs) != 1 {
		t.Errorf("networks %+v, want slot 0's alone", vs)
	}
}

// A join takes a slot above every network the phone is in, so that no
// network it is in yields IPv4 to the new one, and one into a network a
// slot is in already is undone.
func TestAJoinLeavesTheNetworksThePhoneIsIn(t *testing.T) {
	t.Cleanup(func() { keys.SealWith(nil) })
	gossipOnLoopback(t)
	home := filepath.Join(t.TempDir(), "juist")
	p := &vpnPlatform{fakePlatform: fakePlatform{t: t}}
	defer p.close()
	c, err := Start(home, p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	second, err := c.startNetwork(1)
	if err != nil {
		t.Fatal(err)
	}
	createIn(t, "home", netip.MustParsePrefix("198.18.4.0/22"), c.network(0), second)
	if err := c.joinedTwice(second); err == nil || !strings.Contains(err.Error(), "home already") {
		t.Errorf("a second join into home: %v", err)
	}
	if second.s.Status().InNetwork {
		t.Error("the second admission was kept")
	}
	if !c.network(0).s.Status().InNetwork {
		t.Error("undoing the second admission left the first")
	}

	create(t, second, "office", netip.MustParsePrefix("198.18.8.0/22"))
	if err := c.Leave(0); err != nil {
		t.Fatal(err)
	}
	next, made, err := c.freeSlot()
	if err != nil || next.slot != 2 || !made {
		t.Fatalf("with slot 0 free beside office in 1, a join takes %+v (made %v, %v), want slot 2", next, made, err)
	}
	if err := c.drop(next); err != nil {
		t.Fatal(err)
	}
	for _, s := range []int{2, 3} {
		n, _, err := c.freeSlot()
		if err != nil || n.slot != s {
			t.Fatalf("a join takes %+v, %v, want slot %d", n, err, s)
		}
		create(t, n, fmt.Sprintf("net%d", s), netip.MustParsePrefix(fmt.Sprintf("198.18.%d.0/22", 4*s+8)))
	}
	if n, _, err := c.freeSlot(); err != nil || n.slot != 0 {
		t.Fatalf("with every slot above taken, a join takes %+v, %v, want the free slot 0", n, err)
	}
	create(t, c.network(0), "last", netip.MustParsePrefix("198.18.40.0/22"))
	if _, _, err := c.freeSlot(); err == nil {
		t.Error("a fifth network found a slot")
	}
}

// otherDevice is a member no core here runs, answering for names.
func otherDevice(t *testing.T, name string, names ...string) types.NodeRecord {
	t.Helper()
	id, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	x, m, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	var wg types.WGKey
	wg[0] = 1
	return types.NodeRecord{Identity: id.Public(), Name: name, WireGuard: wg, X25519: x, MLKEM: m,
		Signing: new(id.SigningKey()), Names: names}
}

// The app's public-names switch is `juist names on` and `off` for its slot:
// the view lists the names the network points at other members, says why
// each resolves publicly once the phone agreed, and keeps the word across
// a restart.
func TestThePublicNamesSwitchIsTheOwnersWord(t *testing.T) {
	t.Cleanup(func() { keys.SealWith(nil) })
	gossipOnLoopback(t)
	home := filepath.Join(t.TempDir(), "juist")
	p := &vpnPlatform{fakePlatform: fakePlatform{t: t}}
	defer p.close()
	c, err := Start(home, p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { c.Close() }()
	createWith(t, "home", netip.MustParsePrefix("198.18.4.0/22"),
		[]types.NodeRecord{otherDevice(t, "server", "rss.example.org")}, c.network(0))
	public := func(c *Core) (bool, []publicName) {
		vs := statusesOf(t, c)
		if len(vs) != 1 || vs[0].Names == nil {
			return false, nil
		}
		return vs[0].Settings.PublicNames, vs[0].Names.Public
	}
	waitFor(t, "the public name listed, not agreed", func() bool {
		on, ps := public(c)
		return !on && slices.Equal(ps, []publicName{{Name: "rss.example.org", Member: "server"}})
	})

	if err := c.SetPublicNames(0, true); err != nil {
		t.Fatal(err)
	}
	unreached := []publicName{{Name: "rss.example.org", Member: "server", Not: "server is not reachable"}}
	if on, ps := public(c); !on || !slices.Equal(ps, unreached) {
		t.Errorf("agreed, the view says %v %+v", on, ps)
	}

	c.Close()
	if c, err = Start(home, p); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the word kept across a restart", func() bool {
		on, ps := public(c)
		return on && slices.Equal(ps, unreached)
	})

	if err := c.SetPublicNames(0, false); err != nil {
		t.Fatal(err)
	}
	if on, ps := public(c); on || !slices.Equal(ps, []publicName{{Name: "rss.example.org", Member: "server"}}) {
		t.Errorf("taken back, the view says %v %+v", on, ps)
	}
	if err := c.SetPublicNames(1, true); err == nil {
		t.Error("a slot without a network took the word")
	}
}

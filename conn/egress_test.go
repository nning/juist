package conn

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestNoThirdPartyEgress is the M0 exit criterion (docs/05-roadmap.md): a
// working mesh must touch no third-party infrastructure at all. The risk is
// specific — we embed Tailscale's connectivity stack, which in its normal
// configuration reaches out to DERP relays and STUN servers run by Tailscale
// — so this asserts the absence of exactly that.
//
// Two independent checks, because each is weak alone: no DERP connection
// according to magicsock itself, and no socket owned by this process with a
// remote address outside this host. The socket scan does not depend on the
// embedded code reporting honestly, but it cannot see everything either:
// STUN leaves through magicsock's main *unconnected* UDP socket, which shows
// a zero remote address in /proc/net, so STUN/relay egress rests on the
// DERPs() check until the packet capture below exists.
//
// A packet-level capture is the real form of this assertion and needs
// privileges; it lands with the netns harness in M2.
func TestNoThirdPartyEgress(t *testing.T) {
	// Self-check: prove the detector can see an external remote before
	// trusting its silence below. Connecting a UDP socket records the
	// remote address in /proc/net without a single packet leaving the host
	// (and TEST-NET-1 is never routed anyway).
	probe, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		t.Fatalf("dialing self-check probe: %v", err)
	}
	if !externalSockets(t)["192.0.2.1:9"] {
		probe.Close()
		t.Fatal("egress detector failed its self-check: a socket connected to an external address went unseen")
	}
	probe.Close()

	before := externalSockets(t)

	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatalf("a.SetPeers: %v", err)
	}
	if err := b.mgr.SetPeers([]Peer{a.peer()}); err != nil {
		t.Fatalf("b.SetPeers: %v", err)
	}
	if _, ok := pingUntil(t, a, b.pingAddr(), 30*time.Second); !ok {
		t.Fatal("mesh did not come up; an egress assertion over a dead mesh proves nothing")
	}

	// Deterministically kick the lazy paths that would reach out if STUN
	// targets or a DERP map had leaked in: ReSTUN runs the same code a
	// periodic netcheck would, instead of hoping a timer fires inside the
	// window below.
	for _, n := range []*node{a, b} {
		n.mgr.(*tsManager).magic.ReSTUN("egress-test")
	}
	// Give that, and any other lazy background work (endpoint updates,
	// periodic netchecks), a chance to reach out before we look.
	time.Sleep(2 * time.Second)

	for _, n := range []*node{a, b} {
		if got := n.mgr.(*tsManager).magic.DERPs(); got != 0 {
			t.Errorf("node %d holds %d DERP connections, want 0", n.id, got)
		}
	}

	for remote := range externalSockets(t) {
		if !before[remote] {
			t.Errorf("socket with external remote address appeared during the test: %s", remote)
		}
	}
}

// externalSockets returns the remote addresses of sockets owned by this
// process that point somewhere other than this host. It returns a set keyed by
// string so a caller can diff two snapshots.
func externalSockets(t *testing.T) map[string]bool {
	t.Helper()
	mine := socketInodes(t)
	local := hostAddr(t)
	out := map[string]bool{}
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		for inode, rem := range procNetRemotes(t, f) {
			if !mine[inode] {
				continue
			}
			addr := rem.Addr().Unmap()
			if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr == local {
				continue
			}
			out[rem.String()] = true
		}
	}
	return out
}

// socketInodes reports the inode of every socket this process has open.
func socketInodes(t *testing.T) map[uint64]bool {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd: %v", err)
	}
	inodes := map[uint64]bool{}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err != nil {
			continue // the fd can close under us; that is fine
		}
		s, ok := strings.CutPrefix(target, "socket:[")
		if !ok {
			continue
		}
		if n, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64); err == nil {
			inodes[n] = true
		}
	}
	return inodes
}

// procNetRemotes parses one /proc/net table into inode => remote address.
func procNetRemotes(t *testing.T, family string) map[uint64]netip.AddrPort {
	t.Helper()
	body, err := os.ReadFile("/proc/net/" + family)
	if err != nil {
		t.Skipf("cannot read /proc/net/%s: %v", family, err)
	}
	out := map[uint64]netip.AddrPort{}
	for line := range strings.Lines(string(body)) {
		f := strings.Fields(line)
		// sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode
		if len(f) < 10 || f[0] == "sl" {
			continue
		}
		rem, err := parseProcAddr(f[2])
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			continue
		}
		out[inode] = rem
	}
	return out
}

// TestParseProcAddr round-trips addresses through the kernel's /proc/net
// rendering. The in-test encoder implements the kernel's rule — each 32-bit
// word printed as %08X of the u32 as this host holds it in memory — so the
// test is valid on either endianness, and it covers the 16-byte v6 path that
// the in-test self-check probe (udp4) cannot.
func TestParseProcAddr(t *testing.T) {
	for _, s := range []string{"127.0.0.1:53", "192.0.2.7:9", "[2001:db8::1]:443", "[::1]:8080"} {
		want := netip.MustParseAddrPort(s)
		raw := want.Addr().AsSlice()
		var enc strings.Builder
		for i := 0; i < len(raw); i += 4 {
			fmt.Fprintf(&enc, "%08X", binary.NativeEndian.Uint32(raw[i:i+4]))
		}
		fmt.Fprintf(&enc, ":%04X", want.Port())
		got, err := parseProcAddr(enc.String())
		if err != nil {
			t.Errorf("parseProcAddr(%q): %v", enc.String(), err)
			continue
		}
		if got != want {
			t.Errorf("parseProcAddr(%q) = %v, want %v", enc.String(), got, want)
		}
	}
}

// parseProcAddr decodes the "0100007F:0035" form /proc/net uses: hex bytes in
// host byte order, per 32-bit word.
func parseProcAddr(s string) (netip.AddrPort, error) {
	host, portStr, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("no port in %q", s)
	}
	port, err := strconv.ParseUint(portStr, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", host)
	}
	// /proc/net prints each 32-bit word as %08X of the u32 the kernel holds
	// in memory, so decode the printed value and lay it back down in native
	// byte order to recover the network-order bytes. On little-endian hosts
	// that reverses each word; on big-endian hosts it is the identity.
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(raw[i:i+4], binary.BigEndian.Uint32(raw[i:i+4]))
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", host)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

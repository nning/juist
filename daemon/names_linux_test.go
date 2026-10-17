package daemon

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nning/juist/internal/dnsfwd"
	"golang.org/x/net/dns/dnsmessage"
)

// juistd's resolver is bound to its device, which the host's own queries to
// the device's address come in by, and another host's by none: it does not
// start without the device, and answers the host on it, as here on another
// device of the host's with an address.
func TestTheNamesServerIsBoundToTheDevice(t *testing.T) {
	answer := func(q []byte) []byte {
		var p dnsmessage.Parser
		h, _ := p.Start(q)
		qn, _ := p.Question()
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
		b.StartQuestions()
		b.Question(qn)
		m, _ := b.Finish()
		return m
	}
	if s, err := defaultNamesServer("juist-none", nil)(netip.MustParseAddrPort("127.0.0.1:0"), answer, nil); err == nil {
		s.Close()
		t.Fatal("started on a device there is none of")
	}
	dev, addr := deviceWithAddress(t)
	s, err := defaultNamesServer(dev, nil)(netip.AddrPortFrom(addr, 0), answer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.Dial("udp", netip.AddrPortFrom(addr, s.(*dnsfwd.Forwarder).Port()).String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write(nameQuery(t, "n1.home.juist."))
	if _, err := c.Read(make([]byte, 512)); err != nil {
		t.Fatalf("the host is not answered on %s: %v", dev, err)
	}
}

// deviceWithAddress is a device of the host's but the loopback, with an IPv4
// address of its own.
func deviceWithAddress(t *testing.T) (string, netip.Addr) {
	t.Helper()
	ifcs, _ := net.Interfaces()
	for _, ifc := range ifcs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() {
					return ifc.Name, ip.Unmap()
				}
			}
		}
	}
	t.Skip("no device with an IPv4 address but the loopback")
	return "", netip.Addr{}
}

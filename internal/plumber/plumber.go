//go:build unix

// Package plumber lets juistd run unprivileged where the host grants network
// configuration to root alone, as FreeBSD does: a helper that stays root
// creates juist's TUN devices, sets their addresses and routes and destroys
// them, for the daemon, which asks over a socket and receives the device's
// descriptor. The helper does nothing to any other device.
package plumber

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/sys/unix"
)

// EnvFD names the environment variable that gives the daemon the descriptor
// of its end of the helper's socket, and EnvLifeline that of a pipe the
// helper holds the other end of, which reads EOF once the helper is gone.
const (
	EnvFD       = "JUIST_PLUMBER_FD"
	EnvLifeline = "JUIST_PLUMBER_LIFELINE_FD"
)

// maxFrame bounds a request: a route per member of a large network fits.
const maxFrame = 4 << 20

// callTimeout bounds one call, a route set for a large network included; a
// variable for tests.
var callTimeout = 2 * time.Minute

// devicePattern is the devices the helper serves: juist's own.
var devicePattern = regexp.MustCompile(`^juist[0-9]$`)

const (
	opOpen    = "open"
	opAddrs   = "addrs"
	opRoutes  = "routes"
	opServe   = "serve"
	opEgress  = "egress"
	opDNS     = "dns"
	opDestroy = "destroy"
	opAnswers = "answers"
	opListen  = "listen-https"
	opDNS53   = "listen-dns"
	opGuard   = "guard"
)

type request struct {
	Op     string         `cbor:"1,keyasint"`
	Device string         `cbor:"2,keyasint"`
	MTU    int            `cbor:"3,keyasint,omitempty"`
	Addrs  []netip.Prefix `cbor:"4,keyasint,omitempty"`
	Routes []netip.Prefix `cbor:"5,keyasint,omitempty"`
	Src4   netip.Addr     `cbor:"6,keyasint,omitempty"`
	Serve  *ServeSpec     `cbor:"7,keyasint,omitempty"`
	Egress *EgressSpec    `cbor:"8,keyasint,omitempty"`
	DNS    []netip.Addr   `cbor:"9,keyasint,omitempty"`
	Listen netip.Addr     `cbor:"10,keyasint,omitempty"`
	Search []string       `cbor:"11,keyasint,omitempty"`
	Proto  string         `cbor:"12,keyasint,omitempty"`
	Guard  *GuardSpec     `cbor:"13,keyasint,omitempty"`
}

type response struct {
	Err     string `cbor:"1,keyasint,omitempty"`
	Answers string `cbor:"2,keyasint,omitempty"`
}

var decMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// A Client asks the helper; it is safe for concurrent use.
type Client struct {
	mu     sync.Mutex
	c      *net.UnixConn
	broken error         // set once a call went wrong on the wire
	gone   chan struct{} // closed with it
}

// NewClient is a client on f, the daemon's end of the helper's socket.
func NewClient(f *os.File) (*Client, error) {
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("plumber: %w", err)
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("plumber: not a unix socket")
	}
	return &Client{c: uc, gone: make(chan struct{})}, nil
}

// Broken is closed once a call has gone wrong on the wire, as a helper that
// did not answer in time; every call after it fails.
func (c *Client) Broken() <-chan struct{} { return c.gone }

// OpenTUN creates the device name, up and with mtu, destroying a leftover of
// that name first, and returns its descriptor.
func (c *Client) OpenTUN(name string, mtu int) (*os.File, error) {
	f, err := c.call(request{Op: opOpen, Device: name, MTU: mtu})
	if err == nil && f == nil {
		err = errors.New("plumber: no descriptor came with the device")
	}
	return f, err
}

// SetAddrs gives the device exactly addrs.
func (c *Client) SetAddrs(dev string, addrs []netip.Prefix) error {
	_, err := c.call(request{Op: opAddrs, Device: dev, Addrs: addrs})
	return err
}

// SetRoutes routes exactly routes into the device, from src4 for IPv4 where
// it is valid.
func (c *Client) SetRoutes(dev string, routes []netip.Prefix, src4 netip.Addr) error {
	_, err := c.call(request{Op: opRoutes, Device: dev, Routes: routes, Src4: src4})
	return err
}

// SetServe has the host serve as s asks through dev, forwarding with NAT
// behind a pf anchor of juist's, or no longer where s serves nothing.
func (c *Client) SetServe(dev string, s ServeSpec) error {
	_, err := c.call(request{Op: opServe, Device: dev, Serve: &s})
	return err
}

// SetGuard has the host keep dev's overlay to it as g asks, or no longer
// where g holds no address.
func (c *Client) SetGuard(dev string, g GuardSpec) error {
	_, err := c.call(request{Op: opGuard, Device: dev, Guard: &g})
	return err
}

// SetEgress has the host send its traffic outside the overlay as e asks:
// through dev, refused, or by its own routes.
func (c *Client) SetEgress(dev string, e EgressSpec) error {
	_, err := c.call(request{Op: opEgress, Device: dev, Egress: &e})
	return err
}

// SetDNS makes servers, on port 53, the host's resolvers for every name, by
// dev, with search its search domains, or gives the host its own back where
// there are none.
func (c *Client) SetDNS(dev string, servers []netip.Addr, search []string) error {
	_, err := c.call(request{Op: opDNS, Device: dev, DNS: servers, Search: search})
	return err
}

// ListenDNS binds 53, UDP and TCP, at a, an address of dev's, for the
// resolver that answers the host, which may not bind a port below 1024.
func (c *Client) ListenDNS(dev string, a netip.Addr) (net.PacketConn, net.Listener, error) {
	uf, _, err := c.exchange(request{Op: opDNS53, Device: dev, Listen: a, Proto: "udp"})
	if err != nil {
		return nil, nil, err
	}
	defer uf.Close()
	pc, err := net.FilePacketConn(uf)
	if err != nil {
		return nil, nil, err
	}
	tf, _, err := c.exchange(request{Op: opDNS53, Device: dev, Listen: a, Proto: "tcp"})
	if err != nil {
		pc.Close()
		return nil, nil, err
	}
	defer tf.Close()
	ln, err := net.FileListener(tf)
	if err != nil {
		pc.Close()
		return nil, nil, err
	}
	return pc, ln, nil
}

// Answers says why answers to connections that came in by another device
// would not leave by it, as the host's own firewall rules decide; "" where
// they would.
func (c *Client) Answers(dev string) (string, error) {
	_, resp, err := c.exchange(request{Op: opAnswers, Device: dev})
	return resp.Answers, err
}

// Destroy destroys the device, and with it its addresses and routes.
func (c *Client) Destroy(dev string) error {
	_, err := c.call(request{Op: opDestroy, Device: dev})
	return err
}

// Close ends the connection, which has the helper destroy what it made.
func (c *Client) Close() error { return c.c.Close() }

func (c *Client) call(req request) (*os.File, error) {
	f, _, err := c.exchange(req)
	return f, err
}

// ListenHTTPS binds 443/tcp at a, an address of the host's, for the relay
// of the daemon that opened dev, which may not bind a port below 1024.
func (c *Client) ListenHTTPS(dev string, a netip.Addr) (net.Listener, error) {
	f, _, err := c.exchange(request{Op: opListen, Device: dev, Listen: a})
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return net.FileListener(f)
}

func (c *Client) exchange(req request) (*os.File, response, error) {
	body, err := cbor.Marshal(req)
	if err != nil {
		return nil, response{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken != nil {
		return nil, response{}, c.broken
	}
	// A helper that stopped answering would hold every later call; one
	// that answered late would answer the next call with this one's
	// answer, so the connection goes.
	fail := func(err error) (*os.File, response, error) {
		c.broken = fmt.Errorf("plumber: the helper did not answer: %w", err)
		c.c.Close()
		close(c.gone)
		return nil, response{}, c.broken
	}
	if err := c.c.SetDeadline(time.Now().Add(callTimeout)); err != nil {
		return fail(err)
	}
	if err := writeFrame(c.c, body, nil); err != nil {
		return fail(err)
	}
	body, f, err := readFrame(c.c, req.Op == opOpen || req.Op == opListen || req.Op == opDNS53)
	if err != nil {
		if f != nil {
			f.Close()
		}
		return fail(err)
	}
	var resp response
	if err := decMode.Unmarshal(body, &resp); err != nil {
		if f != nil {
			f.Close()
		}
		return nil, response{}, fmt.Errorf("plumber: %w", err)
	}
	if resp.Err != "" {
		if f != nil {
			f.Close()
		}
		return nil, resp, fmt.Errorf("plumber: %s", resp.Err)
	}
	return f, resp, nil
}

// writeFrame writes body, length first, with f's descriptor alongside the
// length. The body goes by Write, which sends all of it: one sendmsg sends
// what the socket's buffer holds, on FreeBSD 8 KiB.
func writeFrame(c *net.UnixConn, body []byte, f *os.File) error {
	head := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	var oob []byte
	if f != nil {
		oob = unix.UnixRights(int(f.Fd()))
	}
	n, oobn, err := c.WriteMsgUnix(head, oob, nil)
	if err == nil && (n != len(head) || oobn != len(oob)) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return err
	}
	_, err = c.Write(body)
	return err
}

// readFrame reads a frame, and a descriptor with it where fd says one may
// come.
func readFrame(c *net.UnixConn, fd bool) ([]byte, *os.File, error) {
	head := make([]byte, 4)
	oob := make([]byte, unix.CmsgSpace(8*4)) // room for extras, to be closed
	n, oobn, flags, _, err := c.ReadMsgUnix(head, oob)
	if err != nil {
		return nil, nil, err
	}
	var f *os.File
	if oobn > 0 {
		f, err = descriptor(oob[:oobn], flags)
		if err != nil {
			return nil, nil, err
		}
		if !fd {
			f.Close()
			return nil, nil, errors.New("a descriptor came unasked")
		}
	}
	if _, err := io.ReadFull(c, head[n:]); err != nil {
		return nil, f, err
	}
	size := binary.BigEndian.Uint32(head)
	if size > maxFrame {
		return nil, f, fmt.Errorf("a frame of %d bytes", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, f, err
	}
	return body, f, nil
}

func descriptor(oob []byte, flags int) (*os.File, error) {
	fd, err := ReceivedFD(oob, flags)
	if err != nil {
		return nil, err
	}
	// Non-blocking, so that the runtime's poller serves it.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "tun"), nil
}

// ReceivedFD is the one descriptor carried by oob, the control messages a
// read returned with flags. Unless they are one message of one descriptor,
// whole, it closes every descriptor it finds in them.
func ReceivedFD(oob []byte, flags int) (int, error) {
	var fds []int
	var err error
	msgs := 0
	for len(oob) >= unix.CmsgLen(0) {
		hdr, data, rest, perr := unix.ParseOneSocketControlMessage(oob)
		if perr != nil {
			err = errors.New("an unreadable control message")
			break
		}
		msgs++
		if got, perr := unix.ParseUnixRights(&unix.SocketControlMessage{Header: hdr, Data: data}); perr == nil {
			fds = append(fds, got...)
		}
		oob = rest
	}
	switch {
	case err != nil:
	case flags&unix.MSG_CTRUNC != 0:
		err = errors.New("a truncated control message")
	case msgs != 1 || len(fds) != 1:
		err = errors.New("not one descriptor")
	default:
		return fds[0], nil
	}
	for _, fd := range fds {
		unix.Close(fd)
	}
	return -1, err
}

// A Host is what the helper does to the host's network, as root.
type Host interface {
	// OpenTUN creates the device, up, with mtu, and returns a descriptor for
	// the daemon and how to destroy the device.
	OpenTUN(name string, mtu int) (f *os.File, destroy func() error, err error)
	AddAddr(dev string, p netip.Prefix) error
	DelAddr(dev string, p netip.Prefix) error
	// AddRoute routes p into dev, from src where valid.
	AddRoute(dev string, p netip.Prefix, src netip.Addr) error
	// DelRoute deletes the route AddRoute made, from src, alone.
	DelRoute(dev string, p netip.Prefix, src netip.Addr) error
	// SetServe serves through dev as s asks, or no longer; destroying the
	// device ends it too.
	SetServe(dev string, s ServeSpec) error
	// SetEgress sends the host's traffic as e asks, uid being juistd's, whose
	// own goes by the host's routes. Refusing outlasts the device.
	SetEgress(dev string, e EgressSpec, uid int) error
	// SetDNS makes servers the host's resolvers by dev, with search its
	// search domains, or no longer.
	SetDNS(dev string, servers []netip.Addr, search []string) error
	// SetGuard keeps dev's overlay to it as g asks, or no longer where g
	// holds no address; destroying the device ends it too.
	SetGuard(dev string, g GuardSpec) error
	// HostAddrs is the addresses of the host's devices but juist's and the
	// loopback, and the gateways of its routes, which no route into a
	// device may take.
	HostAddrs() []netip.Addr
	// Free reports whether no helper holds dev.
	Free(dev string) bool
	// Answers says why answers to what comes in by another device would not
	// leave by it, "" where they would.
	Answers() string
	// ListenHTTPS binds 443/tcp at a and returns the listener's descriptor.
	ListenHTTPS(a netip.Addr) (*os.File, error)
	// ListenDNS binds 53 at a by proto, "udp" or "tcp", and returns the
	// socket's descriptor.
	ListenDNS(a netip.Addr, proto string) (*os.File, error)
}

// device is what the helper made and installed on one device.
type device struct {
	destroy func() error
	addrs   []netip.Prefix
	routes  map[netip.Prefix]netip.Addr
	ownDNS  bool // the host's resolver is the daemon's own, at the device
}

// destroyed destroys d, and gives the host its resolvers back where they
// were the daemon's, which no longer answers; an exit node's stay, so that
// lookups go nowhere rather than to the LAN until juistd is back.
func (d *device) destroyed(h Host, name string) error {
	var err error
	if d.ownDNS {
		err = h.SetDNS(name, nil, nil)
	}
	return errors.Join(err, d.destroy())
}

// Serve answers the daemon on c until it hangs up, or sends what no helper
// takes, and returns how to destroy every device it made. The caller
// destroys them once the daemon is gone: destroying a device waits for its
// descriptor to close. uid is the daemon's, as the caller started it: the
// socket's own credentials are its creator's, the helper's. dev is the
// daemon's device, the one it plumbs alone: another network's daemon has a
// helper of its own; "" for none.
func Serve(c *net.UnixConn, h Host, uid int, dev string, logf func(string, ...any)) (destroy func(), err error) {
	devs := map[string]*device{}
	destroy = func() {
		for name, d := range devs {
			if err := d.destroyed(h, name); err != nil {
				logf("plumber: destroying %s: %v", name, err)
			}
			delete(devs, name)
		}
	}
	if dev != "" && !devicePattern.MatchString(dev) {
		return destroy, fmt.Errorf("%q is no device of juist's", dev)
	}
	return destroy, serve(c, h, devs, uid, dev)
}

func serve(c *net.UnixConn, h Host, devs map[string]*device, uid int, dev string) error {
	for {
		body, f, err := readFrame(c, false)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if f != nil {
			f.Close()
		}
		if err != nil {
			return err
		}
		var req request
		var out *os.File
		var resp response
		err = decMode.Unmarshal(body, &req)
		if err == nil && req.Op == opAnswers {
			// Read alone, of no device in particular.
			resp.Answers = h.Answers()
		} else if err == nil {
			out, err = handle(devs, h, req, uid, dev)
		}
		if err != nil {
			resp.Err = err.Error()
		}
		b, merr := cbor.Marshal(resp)
		if merr != nil {
			return merr
		}
		werr := writeFrame(c, b, out)
		if out != nil {
			out.Close()
		}
		if werr != nil {
			return werr
		}
	}
}

func handle(devs map[string]*device, h Host, req request, uid int, dev string) (*os.File, error) {
	if !devicePattern.MatchString(req.Device) {
		return nil, fmt.Errorf("%q is no device of juist's", req.Device)
	}
	if req.Device != dev {
		return nil, fmt.Errorf("%q is no device of this juistd's", req.Device)
	}
	d := devs[req.Device]
	if req.Op == opEgress && req.Egress != nil {
		if err := checkEgress(*req.Egress); err != nil {
			return nil, err
		}
	}
	if req.Op == opDNS && d == nil && len(req.DNS) == 0 && h.Free(req.Device) {
		// Given back while no device runs; set only with one.
		return nil, h.SetDNS(req.Device, nil, nil)
	}
	if req.Op == opEgress && d == nil && req.Egress != nil && h.Free(req.Device) && len(req.Egress.Capture) == 0 &&
		(req.Egress.Mode == EgressDirect || req.Egress.Mode == EgressRefused) {
		// Refusing, or no longer, before the device is opened or after it
		// went: a stopped mesh's refusal is kept so, routing nothing into a
		// device of no one's. Another helper's device's egress is that
		// helper's.
		return nil, h.SetEgress(req.Device, *req.Egress, uid)
	}
	if req.Op == opOpen {
		if d != nil {
			return nil, fmt.Errorf("%s is open already", req.Device)
		}
		if req.MTU < 1280 || req.MTU > 65535 {
			return nil, fmt.Errorf("an MTU of %d", req.MTU)
		}
		f, destroy, err := h.OpenTUN(req.Device, req.MTU)
		if err != nil {
			return nil, err
		}
		devs[req.Device] = &device{destroy: destroy, routes: map[netip.Prefix]netip.Addr{}}
		return f, nil
	}
	if d == nil {
		return nil, fmt.Errorf("%s was not opened here", req.Device)
	}
	switch req.Op {
	case opDestroy:
		delete(devs, req.Device)
		return nil, d.destroyed(h, req.Device)
	case opAddrs:
		return nil, setAddrs(h, req.Device, d, req.Addrs)
	case opRoutes:
		return nil, setRoutes(h, req.Device, d, req.Routes, req.Src4)
	case opServe:
		if req.Serve == nil {
			return nil, errors.New("nothing to serve")
		}
		// Its own, as the helper set them: an address is written into
		// pf's rules, and one with a zone could say anything there.
		for _, a := range req.Serve.Addrs {
			if !slices.ContainsFunc(d.addrs, func(p netip.Prefix) bool { return p.Addr() == a }) {
				return nil, fmt.Errorf("%q is no address of %s", a, req.Device)
			}
		}
		// Sources are masqueraded onto, and blocked coming in by, every
		// other device: the overlay's alone, lest the LAN or the internet be.
		for _, p := range req.Serve.Sources {
			if !within(p, overlaySpace) {
				return nil, fmt.Errorf("a source %v outside any network's space", p)
			}
		}
		if err := validPrefixes(req.Serve.Local); err != nil {
			return nil, err
		}
		return nil, h.SetServe(req.Device, *req.Serve)
	case opDNS:
		err := setDNS(h, req.Device, req.DNS, req.Search)
		if err == nil {
			d.ownDNS = len(req.DNS) > 0 && !slices.ContainsFunc(req.DNS, func(a netip.Addr) bool {
				return !slices.ContainsFunc(d.addrs, func(p netip.Prefix) bool { return p.Addr() == a })
			})
		}
		return nil, err
	case opDNS53:
		// One of the device's own addresses alone, which the host's
		// resolver is pointed at.
		a := req.Listen
		if !a.IsValid() || a.Zone() != "" || !slices.ContainsFunc(d.addrs, func(p netip.Prefix) bool { return p.Addr() == a }) {
			return nil, fmt.Errorf("%v is no address of %s", a, req.Device)
		}
		if req.Proto != "udp" && req.Proto != "tcp" {
			return nil, fmt.Errorf("no protocol %q", req.Proto)
		}
		return h.ListenDNS(a, req.Proto)
	case opListen:
		// 443 alone, at an address of the host's, never one of the
		// device's own, which the terminator serves.
		a := req.Listen
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() ||
			slices.ContainsFunc(linkSpace, func(s netip.Prefix) bool { return s.Contains(a) }) ||
			slices.ContainsFunc(d.addrs, func(p netip.Prefix) bool { return p.Addr() == a }) ||
			slices.Contains(juistAddrs(), a) {
			return nil, fmt.Errorf("%v is no address for a relay", a)
		}
		return h.ListenHTTPS(a)
	case opGuard:
		if req.Guard == nil {
			return nil, errors.New("nothing to guard")
		}
		// Written into pf's rules, the device's ahead of being set: in the
		// overlay's space alone, lest the LAN's be kept from the LAN.
		for _, a := range slices.Concat(req.Guard.Own, req.Guard.Overlay) {
			if !a.IsValid() || a.Zone() != "" || !within(netip.PrefixFrom(a, a.BitLen()), overlaySpace) {
				return nil, fmt.Errorf("an address %q outside any network's space", a)
			}
		}
		return nil, h.SetGuard(req.Device, *req.Guard)
	case opEgress:
		if req.Egress == nil {
			return nil, errors.New("no egress")
		}
		if req.Egress.Mode == EgressTunnel && len(req.Egress.Capture) == 0 {
			return nil, errors.New("a tunnel capturing nothing")
		}
		return nil, h.SetEgress(req.Device, *req.Egress, uid)
	}
	return nil, fmt.Errorf("no operation %q", req.Op)
}

// juistAddrs are the addresses of every juist device on the host, other
// instances' too, whose 443 is their terminators'.
var juistAddrs = func() []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ifc := range ifs {
		if !devicePattern.MatchString(ifc.Name) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
					out = append(out, ip.Unmap())
				}
			}
		}
	}
	return out
}

// overlaySpace is where a network's addresses lie: the ranges its own IPv4
// prefix may be chosen in (types.ValidateV4Prefix), and ULA.
var overlaySpace = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fc00::/7"),
}

// linkSpace is what the host keeps to itself or its links, which no route
// into a device may take.
var linkSpace = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("::/127"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// hostSpace is what an exit node's capture must leave be: the links, and the
// LAN.
var hostSpace = append(slices.Clone(overlaySpace), linkSpace...)

// within reports whether p is a valid, masked prefix inside one of space.
func within(p netip.Prefix, space []netip.Prefix) bool {
	return p.IsValid() && p.Masked() == p &&
		slices.ContainsFunc(space, func(s netip.Prefix) bool { return s.Bits() <= p.Bits() && s.Contains(p.Addr()) })
}

func validPrefixes(ps []netip.Prefix) error {
	for _, p := range ps {
		if !p.IsValid() {
			return errors.New("an invalid prefix")
		}
	}
	return nil
}

// checkEgress refuses an egress whose capture would take what the host keeps
// to itself and its links, as the LAN, into the device.
func checkEgress(e EgressSpec) error {
	switch e.Mode {
	case EgressDirect, EgressTunnel, EgressRefused:
	default:
		return fmt.Errorf("no egress %q", e.Mode)
	}
	for _, p := range e.Capture {
		if !p.IsValid() || p.Masked() != p || p.Bits() == 0 ||
			slices.ContainsFunc(hostSpace, func(s netip.Prefix) bool { return s.Overlaps(p) }) {
			return fmt.Errorf("a capture of %v", p)
		}
	}
	if err := validPrefixes(e.Local); err != nil {
		return err
	}
	return validPrefixes(e.Subnets)
}

func setDNS(h Host, dev string, servers []netip.Addr, search []string) error {
	for _, s := range servers {
		// An exit node's or juistd's own, the only resolvers a device is
		// given.
		if !s.IsValid() || s.Zone() != "" || !within(netip.PrefixFrom(s, s.BitLen()), overlaySpace) {
			return fmt.Errorf("a resolver %v", s)
		}
	}
	if len(servers) > 3 {
		// All the host's resolver takes.
		servers = servers[:3]
	}
	for _, d := range search {
		// Written into resolv.conf, where a space or a newline would say
		// more than a domain.
		if !searchDomain.MatchString(d) || len(d) > 253 {
			return fmt.Errorf("a search domain %q", d)
		}
	}
	if len(search) > 6 {
		// As many as the host's resolver takes.
		search = search[:6]
	}
	return h.SetDNS(dev, servers, search)
}

// searchDomain is a domain resolv.conf may search.
var searchDomain = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$`)

func setAddrs(h Host, dev string, d *device, want []netip.Prefix) error {
	var errs []error
	for _, p := range slices.Clone(d.addrs) {
		if !slices.Contains(want, p) {
			if err := h.DelAddr(dev, p); err != nil {
				errs = append(errs, err)
				continue
			}
			d.addrs = slices.DeleteFunc(d.addrs, func(q netip.Prefix) bool { return q == p })
		}
	}
	for _, p := range want {
		if !p.IsValid() || slices.Contains(d.addrs, p) {
			continue
		}
		if !p.IsSingleIP() {
			// A wider one would route the rest of it into the device.
			errs = append(errs, fmt.Errorf("an address of more than one host, %v", p))
			continue
		}
		if !within(p, overlaySpace) && !linkLocalOf(p, want) {
			// One of the internet's, or the LAN's, would be the host's own.
			errs = append(errs, fmt.Errorf("an address outside any network's space, %v", p))
			continue
		}
		if err := h.AddAddr(dev, p); err != nil {
			errs = append(errs, err)
			continue
		}
		d.addrs = append(d.addrs, p)
	}
	return errors.Join(errs...)
}

// linkLocalOf reports whether p is the link-local address a member holds
// beside one of its overlay IPv6 addresses among want: fe80::/64 and that
// address's low 64 bits.
func linkLocalOf(p netip.Prefix, want []netip.Prefix) bool {
	if !p.Addr().Is6() || !p.IsSingleIP() || p.Addr().Zone() != "" {
		return false
	}
	ll := p.Addr().As16()
	if ll[0] != 0xfe || ll[1] != 0x80 || [6]byte(ll[2:8]) != [6]byte{} {
		return false
	}
	return slices.ContainsFunc(want, func(q netip.Prefix) bool {
		a := q.Addr().As16()
		return q.Addr().Is6() && q.IsSingleIP() && within(q, overlaySpace) && [8]byte(a[8:]) == [8]byte(ll[8:])
	})
}

func setRoutes(h Host, dev string, d *device, want []netip.Prefix, src4 netip.Addr) error {
	var errs []error
	wanted := map[netip.Prefix]netip.Addr{}
	hosts := h.HostAddrs()
	for _, p := range want {
		switch {
		case !p.IsValid():
			continue
		case p.Bits() == 0:
			// The internet goes into the tunnel by the exit node's own
			// means, which keep the host's traffic apart; not this way.
			errs = append(errs, fmt.Errorf("a default route, %v", p))
			continue
		}
		if slices.ContainsFunc(linkSpace, func(s netip.Prefix) bool { return s.Overlaps(p) }) {
			errs = append(errs, fmt.Errorf("a route of the host's links, %v", p))
			continue
		}
		// The host's LAN whole holds its address. A part of a wider network
		// it is on may be a subnet's, as a DHCP netmask too wide makes it.
		if slices.ContainsFunc(hosts, func(a netip.Addr) bool { return p.Contains(a.WithZone("")) }) {
			errs = append(errs, fmt.Errorf("a route over the host's own LAN, %v", p))
			continue
		}
		src := netip.Addr{}
		if p.Addr().Is4() && src4.Is4() &&
			slices.ContainsFunc(d.addrs, func(a netip.Prefix) bool { return a.Addr() == src4 }) {
			src = src4
		}
		wanted[p.Masked()] = src
	}
	for p, src := range d.routes {
		if _, ok := wanted[p]; ok {
			continue
		}
		if err := h.DelRoute(dev, p, src); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(d.routes, p)
	}
	for p, src := range wanted {
		old, ok := d.routes[p]
		switch {
		case ok && old == src:
			continue
		case ok && h.AddRoute(dev, p, src) == nil:
			// From a new source, beside the old route where the kernel
			// takes several, so the prefix is never without one.
			d.routes[p] = src
			if err := h.DelRoute(dev, p, old); err != nil {
				errs = append(errs, err)
			}
			continue
		case ok:
			if err := h.DelRoute(dev, p, old); err != nil {
				errs = append(errs, err)
				continue
			}
			delete(d.routes, p)
		}
		if err := h.AddRoute(dev, p, src); err != nil {
			errs = append(errs, err)
			continue
		}
		d.routes[p] = src
	}
	return errors.Join(errs...)
}

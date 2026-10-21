// Package resolved points systemd-resolved, over D-Bus, at the resolvers of
// one link, for the domains it routes there or every name, and back. It
// starts no resolved that is not running, and never has polkit ask anyone
// for a password.
package resolved

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	busName = "org.freedesktop.resolve1"
	objPath = "/org/freedesktop/resolve1"
	manager = busName + ".Manager"

	callTimeout = 3 * time.Second
)

var (
	// ErrNotRunning is returned where no resolved holds its bus name.
	ErrNotRunning = errors.New("systemd-resolved is not running")

	// ErrNotAuthorized is returned where resolved, or polkit for it, refused.
	ErrNotAuthorized = errors.New("systemd-resolved refused juistd")

	// ErrNoPolkit is the [ErrNotAuthorized] of a host without polkit, which
	// no rule can turn.
	ErrNoPolkit = fmt.Errorf("%w: polkit is not installed", ErrNotAuthorized)

	// ErrTooOld is returned by a resolved that cannot take a server's port,
	// which is older than systemd 246.
	ErrTooOld = errors.New("systemd-resolved is too old to take a resolver's port")
)

// A Client talks to one resolved. It is not safe for concurrent use.
type Client struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

// Dial connects to the system bus, returning [ErrNotRunning] where resolved
// is not on it. Calls time out one by one: a context given to the connection
// would end it.
func Dial() (*Client, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, noBus(err)
	}
	return Open(conn)
}

// DialContext is [Dial] whose connection, its handshake included, ends with
// ctx: for a client used within it alone.
func DialContext(ctx context.Context) (*Client, error) {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return nil, noBus(err)
	}
	return Open(conn)
}

// noBus is err, but [ErrNotRunning] where there is no system bus to connect
// to, as in a container, which no resolved can be on.
func noBus(err error) error {
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%w: %w", ErrNotRunning, err)
	}
	return err
}

// Open is [Dial] over conn, which the client closes. resolved's bus name is
// activatable, so whether it runs is asked before anything is sent to it.
func Open(conn *dbus.Conn) (*Client, error) {
	var running bool
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, busName).Store(&running); err != nil {
		conn.Close()
		return nil, err
	}
	if !running {
		conn.Close()
		return nil, ErrNotRunning
	}
	return &Client{conn: conn, obj: conn.Object(busName, objPath)}, nil
}

// Close ends the client's connection.
func (c *Client) Close() error { return c.conn.Close() }

type server struct {
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}

type domain struct {
	Domain    string
	RouteOnly bool
}

// A Domain is one a link's servers answer for: a routing domain alone, or a
// search domain too, which single names are tried in.
type Domain struct {
	Name   string
	Search bool
}

// Route makes servers, on the link ifindex, resolved's resolvers for every
// name no other link claims by a longer routing domain.
func (c *Client) Route(ifindex int, servers []netip.AddrPort) error {
	return c.Configure(ifindex, servers, []Domain{{Name: "."}}, true)
}

// Configure makes servers, on the link ifindex, resolved's resolvers for
// domains, and for every name no other link claims where everything; a
// search domain is tried for single names too.
func (c *Client) Configure(ifindex int, servers []netip.AddrPort, domains []Domain, everything bool) error {
	list := make([]server, len(servers))
	for i, s := range servers {
		fam := int32(unix.AF_INET)
		if s.Addr().Is6() {
			fam = unix.AF_INET6
		}
		list[i] = server{Family: fam, Address: s.Addr().AsSlice(), Port: s.Port()}
	}
	if err := c.call("SetLinkDNSEx", int32(ifindex), list); err != nil {
		if isUnknownMethod(err) {
			return ErrTooOld
		}
		return err
	}
	ds := make([]domain, len(domains))
	for i, d := range domains {
		ds[i] = domain{Domain: d.Name, RouteOnly: !d.Search}
	}
	if everything && !slices.ContainsFunc(domains, func(d Domain) bool { return d.Name == "." }) {
		ds = append(ds, domain{".", true})
	}
	// Half-routed, the link would send some names to servers the caller
	// believes unrouted: it goes back whole.
	if err := c.call("SetLinkDomains", int32(ifindex), ds); err != nil {
		return errors.Join(err, c.Revert(ifindex))
	}
	if err := c.call("SetLinkDefaultRoute", int32(ifindex), everything); err != nil && !isUnknownMethod(err) {
		return errors.Join(err, c.Revert(ifindex))
	}
	// Answered unsigned by juistd, the domains would be bogus to a
	// resolved that validates.
	var unsigned []string
	for _, d := range domains {
		if d.Name != "." {
			unsigned = append(unsigned, d.Name)
		}
	}
	if err := c.call("SetLinkDNSSECNegativeTrustAnchors", int32(ifindex), unsigned); err != nil && !isUnknownMethod(err) {
		return errors.Join(err, c.Revert(ifindex))
	}
	return nil
}

// Revert gives the link ifindex back to what resolved configures by itself.
func (c *Client) Revert(ifindex int) error {
	return c.call("RevertLink", int32(ifindex))
}

func (c *Client) call(method string, args ...any) error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	err := c.obj.CallWithContext(ctx, manager+"."+method, 0, args...).Err
	var de dbus.Error
	if errors.As(err, &de) {
		switch de.Name {
		case "org.freedesktop.DBus.Error.AccessDenied", "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired":
			if !c.polkit() {
				return fmt.Errorf("%w: %s", ErrNoPolkit, method)
			}
			return fmt.Errorf("%w: %s", ErrNotAuthorized, method)
		}
	}
	if err != nil {
		return fmt.Errorf("systemd-resolved: %s: %w", method, err)
	}
	return nil
}

// polkit reports whether polkit runs on the bus or can be started there, and
// true where that cannot be told.
func (c *Client) polkit() bool {
	const name = "org.freedesktop.PolicyKit1"
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	bus := c.conn.BusObject()
	var running bool
	if err := bus.CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, name).Store(&running); err != nil || running {
		return true
	}
	var startable []string
	if err := bus.CallWithContext(ctx, "org.freedesktop.DBus.ListActivatableNames", 0).Store(&startable); err != nil {
		return true
	}
	return slices.Contains(startable, name)
}

func isUnknownMethod(err error) bool {
	var de dbus.Error
	return errors.As(err, &de) && de.Name == "org.freedesktop.DBus.Error.UnknownMethod"
}

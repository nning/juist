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
		return nil, err
	}
	return Open(conn)
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
			return fmt.Errorf("%w: %s", ErrNotAuthorized, method)
		}
	}
	if err != nil {
		return fmt.Errorf("systemd-resolved: %s: %w", method, err)
	}
	return nil
}

func isUnknownMethod(err error) bool {
	var de dbus.Error
	return errors.As(err, &de) && de.Name == "org.freedesktop.DBus.Error.UnknownMethod"
}

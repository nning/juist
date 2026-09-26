// Package firewalld asks a running firewalld, over D-Bus, how it treats
// traffic arriving on this host. It changes nothing, starts no firewalld that
// is not running, and never has polkit ask anyone for a password.
package firewalld

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	busName   = "org.fedoraproject.FirewallD1"
	objPath   = "/org/fedoraproject/FirewallD1"
	zoneIface = busName + ".zone"

	// The polkit actions firewalld checks its runtime queries against.
	actionInfo       = busName + ".info"
	actionConfigInfo = busName + ".config.info"
)

var (
	// ErrNotRunning is returned where no firewalld holds its bus name.
	ErrNotRunning = errors.New("firewalld is not running")

	// ErrNotAuthorized is returned for a question polkit would let this
	// process ask only after someone authenticated.
	ErrNotAuthorized = errors.New("not authorized to ask firewalld")
)

// A Client asks one firewalld. It is not safe for concurrent use.
type Client struct {
	conn    *dbus.Conn
	fw      dbus.BusObject
	root    bool
	allowed map[string]bool // polkit's answer per action, asked once
}

// Dial connects to the system bus, returning [ErrNotRunning] where firewalld
// is not on it. ctx bounds the client's whole life: once it is done, every
// call fails.
func Dial(ctx context.Context) (*Client, error) {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	return open(conn, os.Geteuid() == 0)
}

// open asks whether firewalld runs before anything is sent to it: its bus
// name is activatable, so a call would start it.
func open(conn *dbus.Conn, root bool) (*Client, error) {
	var running bool
	if err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, busName).Store(&running); err != nil {
		conn.Close()
		return nil, err
	}
	if !running {
		conn.Close()
		return nil, ErrNotRunning
	}
	return &Client{conn: conn, fw: conn.Object(busName, objPath), root: root, allowed: map[string]bool{}}, nil
}

// Close ends the client's connection.
func (c *Client) Close() error { return c.conn.Close() }

// Zone returns the zone firewalld applies to what arrives on iface: the one
// it is in, else the default zone. An empty iface asks for the default zone.
func (c *Client) Zone(iface string) (string, error) {
	var zone string
	if iface != "" {
		if err := c.call(actionInfo, zoneIface+".getZoneOfInterface", &zone, iface); err != nil || zone != "" {
			return zone, err
		}
	}
	err := c.call(actionInfo, busName+".getDefaultZone", &zone)
	return zone, err
}

// Admits reports whether zone lets proto traffic to port in, by accepting
// everything or by the port. Services and rich rules are not looked into.
func (c *Client) Admits(zone string, port uint16, proto string) (bool, error) {
	// firewalld's own accept-all zone, told apart without config.info rights.
	if zone == "trusted" {
		return true, nil
	}
	var settings map[string]dbus.Variant
	if err := c.call(actionConfigInfo, zoneIface+".getZoneSettings2", &settings, zone); err != nil {
		return false, err
	}
	if target, _ := settings["target"].Value().(string); target == "ACCEPT" {
		return true, nil
	}
	var open bool
	err := c.call(actionConfigInfo, zoneIface+".queryPort", &open, zone, strconv.Itoa(int(port)), proto)
	return open, err
}

// HasService reports whether zone lets the named service in.
func (c *Client) HasService(zone, service string) (bool, error) {
	var open bool
	err := c.call(actionConfigInfo, zoneIface+".queryService", &open, zone, service)
	return open, err
}

func (c *Client) call(action, method string, out any, args ...any) error {
	if err := c.authorize(action); err != nil {
		return err
	}
	err := c.fw.Call(method, dbus.FlagNoAutoStart, args...).Store(out)
	var de dbus.Error
	switch {
	case !errors.As(err, &de):
	case de.Name == "org.freedesktop.DBus.Error.ServiceUnknown", de.Name == "org.freedesktop.DBus.Error.NameHasNoOwner":
		return ErrNotRunning
	case strings.HasSuffix(de.Name, ".NotAuthorizedException"):
		return ErrNotAuthorized
	}
	return err
}

// authorize asks polkit, allowing no interaction, whether firewalld would
// answer action for this connection. firewalld itself asks allowing it, so
// asking it unchecked can put a password dialog before whoever is logged in.
// Root is exempt: firewalld answers it even where polkit does not run.
func (c *Client) authorize(action string) error {
	if c.root {
		return nil
	}
	ok, asked := c.allowed[action]
	if !asked {
		ok = c.polkitAllows(action)
		c.allowed[action] = ok
	}
	if !ok {
		return ErrNotAuthorized
	}
	return nil
}

func (c *Client) polkitAllows(action string) bool {
	subject := struct {
		Kind    string
		Details map[string]dbus.Variant
	}{"system-bus-name", map[string]dbus.Variant{"name": dbus.MakeVariant(c.conn.Names()[0])}}
	var result struct {
		Authorized, Challenge bool
		Details               map[string]string
	}
	const noInteraction = uint32(0)
	err := c.conn.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority").
		Call("org.freedesktop.PolicyKit1.Authority.CheckAuthorization", 0,
			subject, action, map[string]string{}, noInteraction, "").
		Store(&result)
	return err == nil && result.Authorized
}

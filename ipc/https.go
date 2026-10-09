package ipc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// HTTPS is this device's use of 443/tcp: speaking nothing else, and its relay
// serving a public name there. Nil where neither is set.
type HTTPS struct {
	// Only says the device sends nothing but TLS to relays on 443, and
	// Proxy names the HTTP proxy it goes through, without credentials; ""
	// for none.
	Only  bool   `cbor:"1,keyasint,omitempty"`
	Proxy string `cbor:"2,keyasint,omitempty"`

	// Relays are the names of the member relays on 443 the data plane
	// holds, which with Only are the only ones it reaches.
	Relays []string `cbor:"3,keyasint,omitempty"`

	// Name is the public name this device's relay serves on 443, as set.
	// NotAnnounced says why members are not told of it, "" where they are;
	// Listening where 443 is taken, as ADDR:443, or "the ingress" where the
	// ingress hands the name's connections on; ListenError why it is not;
	// and NoCert why the relay holds no certificate for the name, "" once
	// it does.
	Name         string   `cbor:"4,keyasint,omitempty"`
	NotAnnounced string   `cbor:"5,keyasint,omitempty"`
	Listening    []string `cbor:"6,keyasint,omitempty"`
	ListenError  string   `cbor:"7,keyasint,omitempty"`
	NoCert       string   `cbor:"8,keyasint,omitempty"`
}

// HandedOn is what [HTTPS.Listening] says where the ingress takes 443.
const HandedOn = "the ingress"

func (h *HTTPS) forReader() *HTTPS {
	if h == nil {
		return nil
	}
	return &HTTPS{Only: h.Only, Relays: h.Relays, Name: h.Name}
}

// ValidProxy checks a proxy's URL as a setting takes it: "", or http or
// https to a host and an optional port, with credentials at most.
func ValidProxy(s string) error {
	if s == "" {
		return nil
	}
	if len(s) > 2048 {
		return errors.New("a proxy URL over 2048 bytes")
	}
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return fmt.Errorf("%q is no URL", s)
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("%q is no http or https URL", s)
	case u.Hostname() == "" || strings.ContainsAny(u.Host, " \r\n"):
		return fmt.Errorf("%q names no host", s)
	case u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("%q has a path; a proxy is a host and a port", s)
	}
	return nil
}

// RedactProxy is a proxy's URL without its password.
func RedactProxy(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	if _, ok := u.User.Password(); ok {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
	}
	return u.String()
}

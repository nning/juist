//go:build !freebsd

package main

import "github.com/nning/juist/conn"

// split does nothing: only FreeBSD's juistd splits, where no capability
// grants the network alone.
func split([]string) (int, bool) { return 0, false }

// permHint is what gives a device's creation the right it lacked.
const permHint = `creating %q needs CAP_NET_ADMIN: setcap cap_net_admin+ep on this binary, the packaged service, or --tun ""`

func inheritedPlumber() (conn.Plumber, <-chan struct{}, error) { return nil, nil, nil }

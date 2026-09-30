package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/nning/juist/conn"
)

// sshClient is the address of the ssh client this command runs under, from
// SSH_CONNECTION, or from an ancestor's where sudo dropped it. inSSH says it
// runs under sshd at all, as an ancestor named so shows, whose client may be
// unknown: the environment of another user's ancestor cannot be read.
func (a *app) sshClient() (client netip.Addr, inSSH bool) {
	if c, ok := parseSSHConnection(a.getenv("SSH_CONNECTION")); ok {
		return c, true
	}
	pid := os.Getppid()
	for range 16 {
		if pid <= 1 {
			break
		}
		if env, err := a.system(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
			for _, kv := range bytes.Split(env, []byte{0}) {
				if v, ok := bytes.CutPrefix(kv, []byte("SSH_CONNECTION=")); ok {
					if c, ok := parseSSHConnection(string(v)); ok {
						return c, true
					}
				}
			}
		}
		var comm string
		comm, pid = procStat(a, pid)
		if comm == "sshd" || strings.HasPrefix(comm, "sshd-") {
			inSSH = true
		}
	}
	return netip.Addr{}, inSSH
}

// procStat is pid's command name and parent, as Linux's /proc says them, a
// parent of 0 where it says none.
func procStat(a *app, pid int) (string, int) {
	stat, err := a.system(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", 0
	}
	// pid (comm) state ppid ...: comm may hold spaces and parentheses.
	i, j := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
	if i < 0 || j < i {
		return "", 0
	}
	f := strings.Fields(string(stat[j+1:]))
	if len(f) < 2 {
		return "", 0
	}
	ppid, _ := strconv.Atoi(f[1])
	return string(stat[i+1 : j]), ppid
}

func parseSSHConnection(v string) (netip.Addr, bool) {
	f := strings.Fields(v)
	if len(f) != 4 {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(f[0])
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

// cutsSSH says the ssh session this command runs under, by its client's
// address, where using an exit node would send its answers through it,
// overlay aside; an unknown client is taken to be cut, as one of the
// internet's may be.
func (a *app) cutsSSH(overlay []netip.Prefix) (string, bool) {
	client, inSSH := a.sshClient()
	switch {
	case !inSSH:
		return "", false
	case !client.IsValid():
		return "whose client juist cannot see", true
	}
	for _, p := range conn.Internet(true, true, overlay) {
		if p.Contains(client) {
			return "from " + client.String(), true
		}
	}
	return "", false
}

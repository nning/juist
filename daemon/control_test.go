package daemon

import (
	"slices"
	"testing"

	"github.com/nning/juist/ipc"
)

// Every command the IPC wire defines has an entry in the table, and the
// table answers none it does not; each entry admits the operator.
func TestEveryCommandHasAnEntry(t *testing.T) {
	for c := ipc.Command(1); c != 0; c++ {
		cmd, ok := commands[c]
		switch {
		case c.Known() && !ok:
			t.Errorf("%v has no entry", c)
		case !c.Known() && ok:
			t.Errorf("command %d has an entry the wire does not define", uint8(c))
		case ok && (cmd.run == nil || cmd.who&roleOperator == 0):
			t.Errorf("%v runs nothing, or not for the operator", c)
		}
	}
}

// Roles are exclusive where they decide: an operator is one whatever else it
// is, and a reader is no one else.
func TestRolesOf(t *testing.T) {
	s := &Service{selfUID: 10, ingressUID: 20, serveUID: 30}
	s.operator.Store(40)
	for _, c := range []struct {
		who  caller
		want role
		tier tier
	}{
		{caller{}, roleOperator, tierOperator},
		{caller{uid: 0, known: true}, roleOperator, tierOperator},
		{caller{uid: 10, known: true}, roleOperator, tierOperator},
		{caller{uid: 40, known: true}, roleOperator, tierOperator},
		{caller{uid: 20, known: true}, roleIngress, tierIngress},
		{caller{uid: 30, known: true}, roleServe, tierIngress},
		{caller{uid: 50, known: true}, roleReader, tierReader},
	} {
		if got := s.rolesOf(c.who); got != c.want || s.tierOf(c.who) != c.tier {
			t.Errorf("%+v: roles %b, tier %d; want %b, %d", c.who, got, s.tierOf(c.who), c.want, c.tier)
		}
	}
}

// Who is not the operator is answered the status alone as a reader, what is
// published alone as the ingress, and what is served and the status page alone
// as the terminator; each other command is refused it with its own words.
func TestEachRoleIsAnsweredItsCommandsAlone(t *testing.T) {
	answered := map[role][]ipc.Command{
		roleReader:  {ipc.CmdStatus},
		roleIngress: {ipc.CmdPublished},
		roleServe:   {ipc.CmdServing, ipc.CmdStatusPage},
	}
	refusal := map[role]string{
		roleReader:  ipc.ErrNotOperator,
		roleIngress: "the ingress may ask what is published, and nothing else",
		roleServe:   "the terminator may ask what this device serves and its status page, and nothing else",
	}
	s := &Service{selfUID: 10, ingressUID: 20, serveUID: 30}
	whom := map[role]caller{roleReader: {uid: 50, known: true}, roleIngress: {uid: 20, known: true},
		roleServe: {uid: 30, known: true}}
	for r, who := range whom {
		for c, cmd := range commands {
			want := slices.Contains(answered[r], c)
			if got := cmd.who&r != 0; got != want {
				t.Errorf("%v answered to role %b: %v, want %v", c, r, got, want)
			}
			if !want {
				if resp := s.handle(t.Context(), &ipc.Request{Command: c}, who, nil, nil); resp.Err != refusal[r] {
					t.Errorf("%v asked by role %b: %q", c, r, resp.Err)
				}
			}
		}
	}
}

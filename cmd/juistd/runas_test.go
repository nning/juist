package main

import "testing"

// The daemon of an instance runs as the instance's user, the default's as
// juist; what names no instance runs as juist.
func TestTheDaemonRunsAsItsInstancesUser(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "juist"},
		{[]string{"--home", "/var/db/juist"}, "juist"},
		{[]string{"--instance", "juist3", "--home", "/var/db/juist3"}, "juist3"},
		{[]string{"-instance=juist9"}, "juist9"},
		{[]string{"--instance=juist0"}, "juist"},
		{[]string{"--instance", "juist10"}, "juist"},
		{[]string{"--instance"}, "juist"},
		{[]string{"instance", "juist2"}, "juist"},
	} {
		if got := runAs(c.args); got != c.want {
			t.Errorf("runAs(%q) = %q, want %q", c.args, got, c.want)
		}
	}
}

// The helper plumbs the device the daemon makes alone: --tun's, else the
// instance's, else juist0.
func TestTheHelperPlumbsTheDaemonsDeviceAlone(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "juist0"},
		{[]string{"--home", "/var/db/juist", "--tun", "juist0"}, "juist0"},
		{[]string{"--instance", "juist3", "--home", "/var/db/juist3"}, "juist3"},
		{[]string{"--instance=juist4", "-t", "juist7"}, "juist7"},
		{[]string{"--tun=juist2"}, "juist2"},
		{[]string{"--instance", "juist10"}, "juist0"},
	} {
		if got := deviceOf(c.args); got != c.want {
			t.Errorf("deviceOf(%q) = %q, want %q", c.args, got, c.want)
		}
	}
}

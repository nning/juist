package daemon

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/types"
)

// socketDir returns a short-pathed private directory. t.TempDir's paths embed
// the test name and can run past the ~104-byte limit a unix socket address
// has, which fails as a confusing "invalid argument".
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "juist")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// newIPCFixture starts a daemon with its control socket open.
func newIPCFixture(t *testing.T) (*reconcileFixture, string) {
	t.Helper()
	nw := newNetwork(t, 2)
	auth, st := nw.authorityFor(t)
	mgr := &fakeManager{}
	self := nw.devices[0]
	dir := socketDir(t)
	sock := SocketPath(dir)

	d, err := New(Options{
		Authority: auth, Storage: st,
		Identity: self.identity, Recipient: self.recipient, WireGuard: self.wgPrivate,
		Connect:          func(conn.Options) (conn.Manager, error) { return mgr, nil },
		DisableDiscovery: true,
		SocketPath:       sock,
		Logf:             safeLogf(t, ""),
	})
	if err != nil {
		t.Fatalf("starting the daemon: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	go d.ipc.serve()
	if err := d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	return &reconcileFixture{nw: nw, d: d, mgr: mgr, auth: auth, self: self}, sock
}

func TestIPCStatus(t *testing.T) {
	f, sock := newIPCFixture(t)
	resp, err := Call(sock, Request{Command: CmdStatus})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if resp.Status == nil {
		t.Fatal("status reply carries no status")
	}
	if resp.Status.Self != f.self.record.Identity {
		t.Errorf("status is for %v, want %v",
			resp.Status.Self.ShortString(), f.self.record.Identity.ShortString())
	}
	if resp.Status.Members != 2 || resp.Status.NetworkName != "m2-testnet" {
		t.Errorf("status reports %d members of %q, want 2 of m2-testnet",
			resp.Status.Members, resp.Status.NetworkName)
	}
}

// TestIPCInformAppliesARecord is the path an admin's signed record takes when
// a daemon owns the log: the CLI hands it over rather than writing under a
// running daemon.
func TestIPCInformAppliesARecord(t *testing.T) {
	f, sock := newIPCFixture(t)
	victim := f.nw.devices[1]
	removal := f.nw.removeNode(t, f.auth, victim.record.Identity)
	body, err := removal.Encode()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := Call(sock, Request{Command: CmdInform, Records: [][]byte{body}})
	if err != nil {
		t.Fatalf("inform: %v", err)
	}
	if resp.Status.Members != 1 {
		t.Errorf("after the removal the daemon reports %d members, want 1", resp.Status.Members)
	}
	if _, still := f.d.Status().Self, f.auth.State().IsMember(victim.record.Identity); still {
		t.Error("the removed member is still in the log the daemon holds")
	}
}

// TestIPCRejectsGarbage keeps a malformed call from being anything but an
// error message: the socket is the one parser a local unprivileged process can
// reach.
func TestIPCRejectsGarbage(t *testing.T) {
	_, sock := newIPCFixture(t)
	for _, tc := range []struct {
		name string
		req  Request
	}{
		{"no command", Request{}},
		{"unknown command", Request{Command: Command(200)}},
		{"status carrying records", Request{Command: CmdStatus, Records: [][]byte{{1}}}},
		{"inform carrying nothing", Request{Command: CmdInform}},
		{"inform carrying rubbish", Request{Command: CmdInform, Records: [][]byte{{1, 2, 3}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Call(sock, tc.req); err == nil {
				t.Fatal("the daemon accepted a call it must refuse")
			}
		})
	}
	// And the daemon is still answering afterwards.
	if _, err := Call(sock, Request{Command: CmdStatus}); err != nil {
		t.Fatalf("the daemon stopped answering after bad input: %v", err)
	}
}

// TestIPCSocketIsPrivate asserts the two file-system controls
// docs/04-architecture.md requires, since neither shows up in behaviour until
// it is missing.
func TestIPCSocketIsPrivate(t *testing.T) {
	_, sock := newIPCFixture(t)
	info, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("control socket is mode %o, want 600", perm)
	}
	dir, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dir.Mode().Perm(); perm&0o022 != 0 {
		t.Errorf("socket directory is mode %o, writable by group or other", perm)
	}
}

// TestIPCRefusesASharedWritableDirectory covers the case the file mode alone
// cannot: a directory anyone can write to is a directory where anyone can
// replace the socket.
func TestIPCRefusesASharedWritableDirectory(t *testing.T) {
	dir := socketDir(t)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	nw := newNetwork(t, 1)
	auth, st := nw.authorityFor(t)
	_, err := New(Options{
		Authority: auth, Storage: st,
		Identity:  nw.devices[0].identity,
		Recipient: nw.devices[0].recipient,
		WireGuard: nw.devices[0].wgPrivate,
		Connect:   func(conn.Options) (conn.Manager, error) { return &fakeManager{}, nil },

		DisableDiscovery: true,
		SocketPath:       SocketPath(dir),
	})
	if err == nil {
		t.Fatal("the daemon opened a control socket in a world-writable directory")
	}
	if !strings.Contains(err.Error(), "writable by group or other") {
		t.Errorf("error %q does not say what is wrong", err)
	}
}

// TestASecondDaemonOnTheSameHomeIsRefused is the split-brain guard. Without the
// lock, a second daemon unlinks the first's socket and binds its own — the CLI
// then talks to the newcomer while the original keeps a revoked peer's tunnel
// up, two log authorities writing one store. Starting the second must fail
// loudly instead, and the first must still be answering afterwards.
func TestASecondDaemonOnTheSameHomeIsRefused(t *testing.T) {
	f, sock := newIPCFixture(t)
	home := filepath.Dir(sock)

	// A second daemon on the same home, with distinct ephemeral ports so the
	// only thing that can stop it is the home lock, not a port clash.
	nw := newNetwork(t, 1)
	auth, st := nw.authorityFor(t)
	_, err := New(Options{
		Authority: auth, Storage: st,
		Identity:  nw.devices[0].identity,
		Recipient: nw.devices[0].recipient,
		WireGuard: nw.devices[0].wgPrivate,
		Connect:   func(conn.Options) (conn.Manager, error) { return &fakeManager{}, nil },

		DisableDiscovery: true,
		SocketPath:       SocketPath(home),
		Logf:             safeLogf(t, ""),
	})
	if err == nil {
		t.Fatal("a second daemon started on a home another daemon already holds")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("error %q does not name the running daemon", err)
	}

	// The original is unharmed: its socket is still there and still answers.
	if _, err := Call(sock, Request{Command: CmdStatus}); err != nil {
		t.Fatalf("the original daemon stopped answering: %v", err)
	}

	// And once it closes, the home is free for a successor.
	f.d.Close()
	nw2 := newNetwork(t, 1)
	auth2, st2 := nw2.authorityFor(t)
	d2, err := New(Options{
		Authority: auth2, Storage: st2,
		Identity:  nw2.devices[0].identity,
		Recipient: nw2.devices[0].recipient,
		WireGuard: nw2.devices[0].wgPrivate,
		Connect:   func(conn.Options) (conn.Manager, error) { return &fakeManager{}, nil },

		DisableDiscovery: true,
		SocketPath:       SocketPath(home),
		Logf:             safeLogf(t, ""),
	})
	if err != nil {
		t.Fatalf("a successor could not take a released home: %v", err)
	}
	d2.Close()
}

// TestPeerCredRefusesANonSocket keeps the credential check from being skipped
// by anything that is not the unix socket the daemon listens on.
func TestPeerCredRefusesANonSocket(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := checkPeerCred(a); err == nil {
		t.Fatal("the credential check passed on something that is not a unix socket")
	}
}

// TestIPCMessageRoundTrip pins the encoding both halves share.
func TestIPCMessageRoundTrip(t *testing.T) {
	req := Request{Command: CmdInform, Records: [][]byte{{1, 2, 3}}}
	b, err := ipcEncode(&req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRequest(b)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Command != req.Command || len(got.Records) != 1 {
		t.Errorf("round trip changed the request: %+v", got)
	}
	if _, err := DecodeRequest(append(b, 0)); err == nil {
		t.Error("a request with trailing bytes was accepted")
	}

	var id types.Identity
	id[0] = 1
	resp := Response{Status: &Status{Self: id, Epoch: 4}}
	rb, err := ipcEncode(&resp)
	if err != nil {
		t.Fatal(err)
	}
	gotResp, err := DecodeResponse(rb)
	if err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	if gotResp.Status == nil || gotResp.Status.Epoch != 4 {
		t.Errorf("round trip changed the reply: %+v", gotResp)
	}
}

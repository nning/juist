package daemon

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// socketDir returns a short-pathed private directory: a unix socket address
// is capped near 104 bytes, and t.TempDir's paths embed the test name.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "juist")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// serviceFixture is a service over a home that holds device 0's keys and,
// unless it is to start outside any network, the network's log.
type serviceFixture struct {
	nw   *network
	s    *Service
	mgr  *fakeManager
	home string
	sock string
}

func writeDevice(t *testing.T, home string, dev *device) {
	t.Helper()
	wg, err := ecdh.X25519().NewPrivateKey(dev.wgPrivate[:])
	if err != nil {
		t.Fatal(err)
	}
	k, err := keys.NewNode(dev.identity, dev.recipient, wg)
	if err != nil {
		t.Fatal(err)
	}
	k.Name = dev.record.Name
	if err := keys.WriteSecret(filepath.Join(home, keys.NodeKeysFile), k.Lines("test")); err != nil {
		t.Fatal(err)
	}
}

func newServiceFixture(t *testing.T, withLog bool) *serviceFixture {
	t.Helper()
	return newServiceFixtureAs(t, withLog, nil)
}

// newServiceFixtureWith is a service over the network's log whose mesh
// options mutate adjusts.
func newServiceFixtureWith(t *testing.T, mutate func(*Options)) *serviceFixture {
	t.Helper()
	return newServiceFixtureAs(t, true, mutate)
}

func newServiceFixtureAs(t *testing.T, withLog bool, mutate func(*Options)) *serviceFixture {
	t.Helper()
	nw := newNetwork(t, 2)
	home := socketDir(t)
	writeDevice(t, home, nw.devices[0])
	if withLog {
		st, err := store.Open(filepath.Join(home, keys.LogDir))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.FromRecords(st, []types.AUM{nw.genesis}); err != nil {
			t.Fatal(err)
		}
	}
	return startServiceWith(t, nw, home, mutate)
}

func startService(t *testing.T, nw *network, home string) *serviceFixture {
	t.Helper()
	return startServiceWith(t, nw, home, nil)
}

func startServiceWith(t *testing.T, nw *network, home string, mutate func(*Options)) *serviceFixture {
	t.Helper()
	mgr := &fakeManager{}
	mesh := Options{
		Connect:          func(conn.Options) (conn.Manager, error) { return mgr, nil },
		DisableDiscovery: true,
		DisableDHT:       true,
		ReachDelay:       time.Millisecond,
	}
	if mutate != nil {
		mutate(&mesh)
	}
	s, err := NewService(ServiceOptions{
		Home: home,
		Mesh: mesh,
		Logf: safeLogf(t, ""),
	})
	if err != nil {
		t.Fatalf("starting the service: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); s.Close() })
	return &serviceFixture{nw: nw, s: s, mgr: mgr, home: home, sock: ipc.SocketPath(home)}
}

func TestServiceStatus(t *testing.T) {
	f := newServiceFixture(t, true)
	resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	st := resp.Status
	if st.Self != f.nw.devices[0].record.Identity || st.Members != 2 || st.NetworkName != "m2-testnet" {
		t.Errorf("status is %+v", st)
	}
	if !st.InNetwork || !st.CanOperate {
		t.Errorf("a daemon in a network, asked by its own user: InNetwork=%v CanOperate=%v",
			st.InNetwork, st.CanOperate)
	}
}

// A status never waits for a probe: it carries what the background check
// last found, and a Probe from an older client changes nothing. Nothing but a
// status may carry Probe.
func TestServiceStatusCarriesTheLastCheck(t *testing.T) {
	f := newServiceFixture(t, true)
	deadline := time.Now().Add(10 * time.Second)
	for {
		start := time.Now()
		resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus, Probe: true})
		if err != nil {
			t.Fatal(err)
		}
		if took := time.Since(start); took > probeWait {
			t.Fatalf("a status took %v, as long as a probe", took)
		}
		if resp.Status.TunnelsChecked && resp.Status.ReachChecked > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no background check reached the status")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdLog, Probe: true}); err == nil {
		t.Fatal("a log request carrying Probe was served")
	}
}

// TestServiceInformAppliesARecord is the path an admin's signed record takes:
// the CLI hands it over rather than writing under a running daemon.
func TestServiceInformAppliesARecord(t *testing.T) {
	f := newServiceFixture(t, true)
	auth, _ := f.nw.authorityFor(t)
	removal := f.nw.removeNode(t, auth, f.nw.devices[1].record.Identity)
	body, err := removal.Encode()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdInform, Records: [][]byte{body}})
	if err != nil {
		t.Fatalf("inform: %v", err)
	}
	if resp.Status.Members != 1 {
		t.Errorf("after the removal the daemon reports %d members, want 1", resp.Status.Members)
	}
}

// TestServiceRejectsGarbage keeps a malformed call from being anything but an
// error: the socket is the one parser every local user can reach.
func TestServiceRejectsGarbage(t *testing.T) {
	f := newServiceFixture(t, true)
	for _, tc := range []struct {
		name string
		req  ipc.Request
	}{
		{"no command", ipc.Request{}},
		{"unknown command", ipc.Request{Command: ipc.Command(200)}},
		{"status carrying records", ipc.Request{Command: ipc.CmdStatus, Records: [][]byte{{1}}}},
		{"inform carrying nothing", ipc.Request{Command: ipc.CmdInform}},
		{"inform carrying rubbish", ipc.Request{Command: ipc.CmdInform, Records: [][]byte{{1, 2, 3}}}},
		{"join without an invite", ipc.Request{Command: ipc.CmdJoin}},
		{"an operator on a status call", ipc.Request{Command: ipc.CmdStatus, OperatorUID: 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ipc.Call(f.sock, tc.req); err == nil {
				t.Fatal("the daemon accepted a call it must refuse")
			}
		})
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus}); err != nil {
		t.Fatalf("the daemon stopped answering after bad input: %v", err)
	}
}

// TestSocketIsOpenAndCallsAreChecked: any local user may connect, which is
// what lets "juist status" work unprivileged, and so every call is checked.
func TestSocketIsOpenAndCallsAreChecked(t *testing.T) {
	f := newServiceFixture(t, true)
	info, err := os.Lstat(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != socketMode() {
		t.Errorf("control socket is mode %o, want %o", perm, socketMode())
	}

	stranger := caller{uid: 4242, known: true}
	if f.s.selfUID == stranger.uid {
		t.Skip("the test user happens to have the stranger's uid")
	}
	ask := func(who caller, req ipc.Request) ipc.Response {
		return f.s.handle(context.Background(), &req, who, func(*ipc.Event) error { return nil }, nil)
	}
	if resp := ask(stranger, ipc.Request{Command: ipc.CmdStatus}); resp.Status == nil || resp.Status.CanOperate {
		t.Fatalf("a stranger's status call: %+v", resp)
	}
	for _, cmd := range []ipc.Command{ipc.CmdLog, ipc.CmdSelf, ipc.CmdBootstrap, ipc.CmdRotate, ipc.CmdUnstage, ipc.CmdInform, ipc.CmdCreate, ipc.CmdJoin,
		ipc.CmdReset} {
		if resp := ask(stranger, ipc.Request{Command: cmd}); resp.Err != ipc.ErrNotOperator {
			t.Errorf("a stranger's %v call got %+v", cmd, resp)
		}
	}
	for _, cmd := range []ipc.Command{ipc.CmdSetOperator, ipc.CmdCreate, ipc.CmdJoin} {
		req := ipc.Request{Command: cmd, SetOperator: true, OperatorUID: stranger.uid, Invite: "1-a-b-c"}
		if resp := ask(stranger, req); resp.Err == "" {
			t.Errorf("a stranger appointed itself operator through %v", cmd)
		}
	}
	if f.s.operator.Load() != 0 {
		t.Fatal("a stranger's call left an operator appointed")
	}

	// Root appoints the stranger, which may then operate but not appoint.
	root := caller{uid: 0, known: true}
	if resp := ask(root, ipc.Request{Command: ipc.CmdSetOperator, SetOperator: true, OperatorUID: stranger.uid}); resp.Err != "" {
		t.Fatalf("root could not appoint an operator: %s", resp.Err)
	}
	if resp := ask(stranger, ipc.Request{Command: ipc.CmdLog}); resp.Err != "" || len(resp.Records) != 1 {
		t.Fatalf("the operator's log call: %+v", resp)
	}
	if resp := ask(stranger, ipc.Request{Command: ipc.CmdSetOperator, SetOperator: true, OperatorUID: 4343}); resp.Err == "" {
		t.Fatal("an operator appointed someone else")
	}
	if st := ask(stranger, ipc.Request{Command: ipc.CmdStatus}).Status; !st.CanOperate || st.Operator == "" {
		t.Fatalf("the operator's status: %+v", st)
	}

	// The appointment survives a restart.
	if got := loadOperator(filepath.Join(f.home, statedir.OperatorFile), t.Logf); got != stranger.uid {
		t.Fatalf("the persisted operator is %d", got)
	}
}

func TestRefusesASharedWritableSocketDirectory(t *testing.T) {
	nw := newNetwork(t, 1)
	home := socketDir(t)
	writeDevice(t, home, nw.devices[0])
	sockDir := socketDir(t)
	if err := os.Chmod(sockDir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err := NewService(ServiceOptions{Home: home, Socket: filepath.Join(sockDir, "s")})
	if err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("a socket in a world-writable directory got %v", err)
	}
}

// TestASecondServiceOnTheSameHomeIsRefused is the split-brain guard: two log
// authorities on one store must fail loudly, and the first keep answering.
func TestASecondServiceOnTheSameHomeIsRefused(t *testing.T) {
	f := newServiceFixture(t, true)
	_, err := NewService(ServiceOptions{Home: f.home, Socket: filepath.Join(socketDir(t), "s")})
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("a second service on the same home got %v", err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus}); err != nil {
		t.Fatalf("the first service stopped answering: %v", err)
	}
	f.s.Close()
	s2, err := NewService(ServiceOptions{Home: f.home})
	if err != nil {
		t.Fatalf("a successor could not take a released home: %v", err)
	}
	s2.Close()
}

func TestPeerOfRefusesANonSocket(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := peerOf(a); err == nil {
		t.Fatal("the credential check passed on something that is not a unix socket")
	}
}

// TestAServiceOutsideANetworkCreatesOne: a fresh device waits, and becomes a
// network's first member from a genesis record that admits it — and only
// from one that does.
func TestAServiceOutsideANetworkCreatesOne(t *testing.T) {
	f := newServiceFixture(t, false)
	st, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus})
	if err != nil || st.Status.InNetwork {
		t.Fatalf("a fresh service: %+v, %v", st.Status, err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdLog}); err == nil {
		t.Fatal("a service in no network returned a log")
	}

	// A genesis naming another device is refused.
	other := newNetwork(t, 1)
	body, _ := other.genesis.Encode()
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdCreate, Records: [][]byte{body}}); err == nil {
		t.Fatal("created a network that does not admit this device")
	}
	body, _ = f.nw.genesis.Encode()
	resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdCreate, Records: [][]byte{body}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !resp.Status.InNetwork || resp.Status.NotMember || f.s.Mesh() == nil {
		t.Fatalf("after create: %+v", resp.Status)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdCreate, Records: [][]byte{body}}); err == nil {
		t.Fatal("created a second network over the first")
	}
}

// TestRotationIsAdoptedWithoutARestart: the device stages its keys and signs
// its part, an admin completes the record, and once the log names the new
// keys the running mesh takes them by itself, keeping its NAT-traversal key.
func TestRotationIsAdoptedWithoutARestart(t *testing.T) {
	f := newServiceFixture(t, true)
	before := f.nw.devices[0].record.WireGuard
	mesh := f.s.Mesh()
	disco := mesh.discoPublic
	resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdRotate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdRotate}); err == nil {
		t.Fatal("a second rotation was staged over the first")
	}
	rec, err := types.DecodeUnsignedAUM(resp.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if !rec.VerifySignature(f.nw.devices[0].record.Identity, f.nw.devices[0].record.Signing) {
		t.Fatal("the device did not sign its own rotation")
	}
	if err := rec.SignUnder(f.nw.admin, types.CurrentSchema); err != nil {
		t.Fatal(err)
	}
	body, _ := rec.Encode()
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdInform, Records: [][]byte{body}}); err != nil {
		t.Fatal(err)
	}
	st := f.s.Mesh().Status()
	state, _ := f.s.Mesh().TrustedState()
	self, _ := state.Node(f.nw.devices[0].record.Identity)
	if st.StaleKeys || self.WireGuard == before {
		t.Fatalf("after the rotation: stale=%v, the log's key changed=%v", st.StaleKeys, self.WireGuard != before)
	}
	k, err := keys.LoadNode(filepath.Join(f.home, keys.NodeKeysFile))
	if err != nil || !k.NamedBy(&self) {
		t.Fatalf("the live key file does not hold the keys the log names: %v", err)
	}
	if f.s.Mesh() != mesh || mesh.discoPublic != disco {
		t.Fatal("the mesh restarted to take the new keys")
	}
	set := f.mgr.selfSet()
	if len(set) != 1 || !set[0].NodeKey.Equal(conn.NodeKeyFromRaw32([32]byte(k.WGPrivate.Bytes()))) {
		t.Fatalf("the data plane was given %d new selves, not the key the log names", len(set))
	}
	x, m, err := mesh.own.Load().recipient.Public()
	if err != nil || mesh.own.Load().wg != self.WireGuard || x != self.X25519 || m != self.MLKEM {
		t.Fatal("the mesh runs on keys the log does not name")
	}
}

func TestAnAbandonedRotationLeavesNothing(t *testing.T) {
	f := newServiceFixture(t, true)
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdRotate, Identity: true}); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(f.home, keys.NodeKeysFile+keys.StagedSuffix)
	if _, err := os.Stat(staged); err != nil {
		t.Fatal("nothing was staged")
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdUnstage}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatal("the abandoned keys are still staged")
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdRotate}); err != nil {
		t.Fatalf("a new rotation after abandoning one: %v", err)
	}
}

// TestARemovedDeviceWaitsToRejoin: after a restart on a log that no longer
// lists it, the service stays up, holding the log, and says so.
func TestARemovedDeviceWaitsToRejoin(t *testing.T) {
	nw := newNetwork(t, 2)
	home := socketDir(t)
	writeDevice(t, home, nw.devices[0])
	st, err := store.Open(filepath.Join(home, keys.LogDir))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := log.FromRecords(st, []types.AUM{nw.genesis})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Inform(nw.removeNode(t, auth, nw.devices[0].record.Identity)); err != nil {
		t.Fatal(err)
	}
	f := startService(t, nw, home)
	resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Status.InNetwork || !resp.Status.NotMember || f.s.Mesh() != nil {
		t.Fatalf("a removed device's service: %+v", resp.Status)
	}
}

// TestReadersCannotCrowdOutOperators: slots are handed out by who is asking,
// so a user flooding the socket fills only the readers' pool, and only their
// own share of it.
func TestReadersCannotCrowdOutOperators(t *testing.T) {
	s := &ipcServer{
		operators: newPool(maxIPCClients, maxOperatorsPerUser),
		readers:   newPool(maxReaderClients, maxClientsPerUser),
	}
	flooder, other := caller{uid: 4242, known: true}, caller{uid: 4343, known: true}
	for i := 0; i < maxClientsPerUser; i++ {
		if _, ok := s.admit(flooder, tierReader); !ok {
			t.Fatal("a reader was refused its own share")
		}
	}
	if _, ok := s.admit(flooder, tierReader); ok {
		t.Fatal("one reader took more than its share of the pool")
	}
	release, ok := s.admit(other, tierReader)
	if !ok {
		t.Fatal("another reader was locked out by the first")
	}
	release()
	if _, ok := s.admit(caller{uid: 0, known: true}, tierOperator); !ok {
		t.Fatal("root was refused while readers held their pool")
	}
}

// TestTheOperatorCannotLockRootOut: the operator holding every connection it
// may still leaves root the slots to take the appointment back.
func TestTheOperatorCannotLockRootOut(t *testing.T) {
	s := &ipcServer{
		operators: newPool(maxIPCClients, maxOperatorsPerUser),
		readers:   newPool(maxReaderClients, maxClientsPerUser),
	}
	operator := caller{uid: 1000, known: true}
	held := 0
	for {
		if _, ok := s.admit(operator, tierOperator); !ok {
			break
		}
		held++
	}
	if held >= maxIPCClients {
		t.Fatalf("the operator took all %d slots", held)
	}
	if _, ok := s.admit(caller{uid: 0, known: true}, tierOperator); !ok {
		t.Fatal("root was locked out by the operator")
	}
}

// TestAMeshThatFailsToStartIsRetried: a network created where the tunnels
// cannot start yet is held, reported, and started once they can.
func TestAMeshThatFailsToStartIsRetried(t *testing.T) {
	nw := newNetwork(t, 2)
	home := socketDir(t)
	writeDevice(t, home, nw.devices[0])
	var fail atomic.Bool
	fail.Store(true)
	s, err := NewService(ServiceOptions{Home: home, Mesh: Options{
		Connect: func(conn.Options) (conn.Manager, error) {
			if fail.Load() {
				return nil, os.ErrPermission
			}
			return &fakeManager{}, nil
		},
		DisableDiscovery: true, DisableDHT: true,
	}, Logf: safeLogf(t, "")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	body, _ := nw.genesis.Encode()
	resp, err := ipc.Call(ipc.SocketPath(home), ipc.Request{Command: ipc.CmdCreate, Records: [][]byte{body}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if st := resp.Status; !st.InNetwork || st.NotMember || st.StartError == "" {
		t.Fatalf("a created network whose tunnels failed: %+v", st)
	}
	fail.Store(false)
	s.retryMesh()
	if s.Mesh() == nil || s.Status().StartError != "" {
		t.Fatal("the mesh was not started once it could be")
	}
}

// TestHangingUpEndsAJoin: the CLI's Ctrl-C closes the stream, and the daemon
// stops the join it was running for it.
func TestHangingUpEndsAJoin(t *testing.T) {
	f := newServiceFixture(t, false)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { // a host that accepts and says nothing
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	link := "juist:AAAAAAAAAAAAAAAAAAAAAA@" + ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := ipc.Stream(ctx, f.sock, ipc.Request{Command: ipc.CmdJoin, Invite: link}, func(*ipc.Event) {})
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled join succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling did not end the stream")
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.s.Status().Joining {
		if time.Now().After(deadline) {
			t.Fatal("the daemon kept joining after the caller hung up")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestAnAbandonedRotationApprovedAnywayIsAdopted: the record carries this
// device's signature, so an admin can still approve it; the keys it names
// were archived, not deleted, and the device switches to them.
func TestAnAbandonedRotationApprovedAnywayIsAdopted(t *testing.T) {
	f := newServiceFixture(t, true)
	resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdRotate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdUnstage}); err != nil {
		t.Fatal(err)
	}
	rec, err := types.DecodeUnsignedAUM(resp.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.SignUnder(f.nw.admin, types.CurrentSchema); err != nil {
		t.Fatal(err)
	}
	body, _ := rec.Encode()
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdInform, Records: [][]byte{body}}); err != nil {
		t.Fatal(err)
	}
	state, _ := f.s.Mesh().TrustedState()
	self, _ := state.Node(f.nw.devices[0].record.Identity)
	k, err := keys.LoadNode(filepath.Join(f.home, keys.NodeKeysFile))
	if err != nil || !k.NamedBy(&self) {
		t.Fatalf("the device does not hold the keys the approved rotation names: %v", err)
	}
}

// A second abandoned rotation must not overwrite the first one's keys: its
// record carries this device's signature and can still be approved, and a
// log naming keys nobody holds cuts the device off.
func TestAbandoningTwiceKeepsBothKeySets(t *testing.T) {
	f := newServiceFixture(t, true)
	first, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdRotate})
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []ipc.Command{ipc.CmdUnstage, ipc.CmdRotate, ipc.CmdUnstage} {
		if _, err := ipc.Call(f.sock, ipc.Request{Command: cmd}); err != nil {
			t.Fatal(err)
		}
	}
	rec, err := types.DecodeUnsignedAUM(first.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.SignUnder(f.nw.admin, types.CurrentSchema); err != nil {
		t.Fatal(err)
	}
	body, _ := rec.Encode()
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdInform, Records: [][]byte{body}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*rotationCheckInterval, "the first abandoned keys to be adopted", func() bool {
		m := f.s.Mesh()
		if m == nil {
			return false
		}
		state, err := m.TrustedState()
		if err != nil {
			return false
		}
		self, _ := state.Node(f.nw.devices[0].record.Identity)
		k, err := keys.LoadNode(filepath.Join(f.home, keys.NodeKeysFile))
		return err == nil && k.NamedBy(&self)
	})
}

// An abandoned identity rotation approved while the daemon was down leaves
// the old identity no member, so no mesh starts to adopt the new one from:
// the service has to promote the keys without it.
func TestAnIdentityRotationApprovedWhileDownIsAdopted(t *testing.T) {
	f := newServiceFixture(t, true)
	resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdRotate, Identity: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdUnstage}); err != nil {
		t.Fatal(err)
	}
	f.s.Close()
	rec, err := types.DecodeUnsignedAUM(resp.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.SignUnder(f.nw.admin, types.CurrentSchema); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(f.home, keys.LogDir))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := log.Open(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Inform(rec); err != nil {
		t.Fatal(err)
	}
	g := startService(t, f.nw, f.home)
	waitFor(t, 3*rotationCheckInterval, "the mesh to start on the approved identity", func() bool {
		return g.s.Mesh() != nil
	})
}

// A join that fails appoints nobody: a mistyped code must not leave an
// operator behind.
func TestAFailedJoinAppointsNoOperator(t *testing.T) {
	f := newServiceFixture(t, false)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing answers there
	req := ipc.Request{Command: ipc.CmdJoin, Invite: "juist:AAAAAAAAAAAAAAAAAAAAAA@" + addr,
		SetOperator: true, OperatorUID: 4242}
	resp := f.s.handle(context.Background(), &req, caller{uid: 0, known: true}, func(*ipc.Event) error { return nil }, nil)
	if resp.Err == "" {
		t.Fatal("a join to nobody succeeded")
	}
	if op := f.s.operator.Load(); op != 0 {
		t.Fatalf("the failed join appointed uid %d", op)
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.OperatorFile)); !os.IsNotExist(err) {
		t.Fatalf("the failed join wrote the operator file: %v", err)
	}
}

// A daemon that hangs up while the caller is still busy with its reports
// ends the call: the reader must not drop the error that says so when the
// frames it has read are still waiting to be taken.
func TestAHangUpEndsABusyConversation(t *testing.T) {
	sock := filepath.Join(socketDir(t), "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		if _, err := ipc.ReadMessage(c, ipc.MaxRequest); err == nil {
			for range 9 {
				_ = ipc.WriteMessage(c, &ipc.Response{Event: &ipc.Event{Kind: ipc.EventInviteFailed}}, ipc.MaxResponse)
			}
		}
		c.Close()
	}()
	done := make(chan error, 1)
	go func() {
		_, err := ipc.Converse(context.Background(), sock, ipc.Request{Command: ipc.CmdInvite},
			func(ctx context.Context, _ *ipc.Event, _ func(ipc.Request) error) error {
				<-ctx.Done() // busy until the reader has seen the hang-up
				return nil
			})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a hung-up call succeeded")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not end after the daemon hung up")
	}
}

// A CLI working on a state directory itself holds it for as long as it
// works: juistd cannot start underneath it, and while juistd runs the CLI is
// refused, however the two interleave. CLIs share the directory.
func TestTheHomeIsHeldByOneKindOfWriter(t *testing.T) {
	home := socketDir(t)
	cli, err := statedir.ShareHome(home)
	if err != nil {
		t.Fatal(err)
	}
	other, err := statedir.ShareHome(home)
	if err != nil {
		t.Fatalf("a second CLI was refused: %v", err)
	}
	other.Close()
	if l, err := lockHome(home); err == nil {
		l.Close()
		t.Fatal("juistd started on a directory a CLI works on")
	}
	cli.Close()
	d, err := lockHome(home)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := statedir.ShareHome(home); !errors.Is(err, statedir.ErrHomeInUse) {
		t.Fatalf("a CLI worked on a directory juistd runs from: %v", err)
	}
}

// juistd refuses a home with admin keys in it, whatever the home's path: a
// glob over a path with metacharacters in it would have found none.
func TestAdminKeysAreFoundUnderAnyPath(t *testing.T) {
	home := filepath.Join(socketDir(t), "home[1]")
	if err := os.MkdirAll(filepath.Join(home, keys.AdminsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, keys.AdminsDir, "a.key"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewService(ServiceOptions{Home: home, Socket: filepath.Join(socketDir(t), "s")})
	if err == nil || !strings.Contains(err.Error(), "holds admin keys") {
		t.Fatalf("a home at %s with an admin key got %v", home, err)
	}
}

// A reset leaves the state directory as a fresh install would: new keys, no
// network, no operator, and nothing else but the lock and the socket. A
// member is reset only when forced, since the others keep listing it.
func TestServiceResetIsAFreshInstall(t *testing.T) {
	f := newServiceFixture(t, true)
	before := f.s.Status().Self
	ask := func(req ipc.Request) ipc.Response {
		return f.s.handle(context.Background(), &req, caller{uid: 0, known: true}, func(*ipc.Event) error { return nil }, nil)
	}
	if resp := ask(ipc.Request{Command: ipc.CmdSetOperator, SetOperator: true, OperatorUID: 4242}); resp.Err != "" {
		t.Fatal(resp.Err)
	}
	if resp := ask(ipc.Request{Command: ipc.CmdReset}); resp.Err != ipc.ErrStillMember {
		t.Fatalf("a member was reset unforced: %+v", resp)
	}
	// Another instance's home inside this one is another network's device.
	other := filepath.Join(f.home, "juist3", keys.NodeKeysFile)
	if err := os.MkdirAll(filepath.Dir(other), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := f.s.Status(); !st.InNetwork {
		t.Fatal("a refused reset left the network")
	}

	resp := ask(ipc.Request{Command: ipc.CmdReset, Force: true})
	if resp.Err != "" {
		t.Fatal(resp.Err)
	}
	st := resp.Status
	if st.InNetwork || st.Self == before || st.Operator != "" || f.s.operator.Load() != 0 {
		t.Fatalf("after the reset: InNetwork=%v, same identity=%v, operator=%q", st.InNetwork, st.Self == before,
			st.Operator)
	}
	entries, err := os.ReadDir(f.home)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case statedir.LockName, ipc.SocketName, keys.NodeKeysFile, keys.LogDir, "juist3":
		default:
			t.Errorf("%s survived the reset", e.Name())
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("the reset took another instance's home with it: %v", err)
	}
	if _, has, err := f.s.store.Anchor(); err != nil || has {
		t.Fatalf("the log survived the reset (%v)", err)
	}
}

// A device the network removed is reset without force: nothing lists it.
func TestServiceResetsARemovedDevice(t *testing.T) {
	f := newServiceFixture(t, true)
	auth, _ := f.nw.authorityFor(t)
	removal := f.nw.removeNode(t, auth, f.nw.devices[0].record.Identity)
	body, err := removal.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdInform, Records: [][]byte{body}}); err != nil {
		t.Fatalf("inform: %v (%+v)", err, resp)
	}
	if st := f.s.Status(); !st.NotMember {
		t.Fatal("the removal did not reach the service")
	}
	if resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdReset}); err != nil || resp.Status.InNetwork {
		t.Fatalf("a removed device's reset: %v (%+v)", err, resp.Status)
	}
}

// When the log gives this device other overlay addresses than the data plane
// holds, the running mesh moves onto them: the device, and the log sync
// listener, through which nothing else could fix it.
func TestTheMeshMovesOntoNewOverlayAddresses(t *testing.T) {
	f := newServiceFixture(t, true)
	before := f.s.Mesh()
	if before == nil {
		t.Fatal("no mesh")
	}
	f.s.followAddrs()
	if len(f.mgr.selfSet()) != 0 {
		t.Fatal("the data plane was given addresses it holds")
	}
	logs := before.heldAddrs()
	holds(f.s, netip.MustParsePrefix("198.18.9.9/32"))
	f.s.followAddrs()
	if f.s.Mesh() != before {
		t.Fatal("the mesh restarted to move onto new addresses")
	}
	set := f.mgr.selfSet()
	if len(set) != 1 || !slices.Equal(set[0].Addrs, logs) {
		t.Fatalf("the data plane was given %+v, want the log's %v", set, logs)
	}
	if before.addrsMoved() || !slices.Equal(before.Status().Addrs, logs) {
		t.Errorf("the mesh holds %v and says %v, not the log's %v", before.heldAddrs(), before.Status().Addrs, logs)
	}
}

// A move said by a reconcile that read the addresses before the last one
// does not keep the next from being said.
func TestAMoveSaidLateIsForgotten(t *testing.T) {
	f := newServiceFixture(t, true)
	f.s.Mesh().movedSaid.Store(true)
	f.s.followAddrs()
	if f.s.Mesh().movedSaid.Load() {
		t.Fatal("a move said with nothing moved keeps the next from being said")
	}
}

// A rotation said by a reconcile that read the keys before the last one
// does not keep the next from being said.
func TestARotationSaidLateIsForgotten(t *testing.T) {
	f := newServiceFixture(t, true)
	f.s.Mesh().keysSaid.Store(true)
	f.s.adoptRotation()
	if f.s.Mesh().keysSaid.Load() {
		t.Fatal("a rotation said with nothing rotated keeps the next from being said")
	}
}

// holds has s's mesh hold addrs, as before a renumbering.
func holds(s *Service, addrs ...netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mesh.held.Store(&addrs)
}

// restartMesh restarts s's mesh as a change of keys does.
func restartMesh(s *Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restartMeshLocked(nil, "a test")
}

// A state directory without node keys is not a juist home, and is not wiped:
// a misconfigured --home must not take someone's files with it.
func TestResetRefusesADirectoryThatIsNoJuistHome(t *testing.T) {
	f := newServiceFixture(t, true)
	if err := os.Remove(filepath.Join(f.home, keys.NodeKeysFile)); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(f.home, "somebodys-file")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := f.s.handle(context.Background(), &ipc.Request{Command: ipc.CmdReset, Force: true}, caller{uid: 0, known: true},
		func(*ipc.Event) error { return nil }, nil)
	if resp.Err == "" {
		t.Fatal("a directory without node keys was reset")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("the refused reset deleted a file: %v", err)
	}
}

// Status is anyone's to read and the log is not: a local user who does not
// operate this device is told no member list.
func TestAStrangersStatusCarriesNoMemberList(t *testing.T) {
	f := newServiceFixture(t, true)
	stranger := caller{uid: uint32(os.Getuid()) + 4242, known: true}
	ask := func(who caller) *ipc.Status {
		return f.s.handle(context.Background(), &ipc.Request{Command: ipc.CmdStatus}, who,
			func(*ipc.Event) error { return nil }, nil).Status
	}
	if st := ask(caller{uid: 0, known: true}); len(st.Devices) == 0 {
		t.Fatal("root's status carries no member list, so the test tests nothing")
	}
	if st := ask(stranger); len(st.Devices) != 0 {
		t.Errorf("a stranger's status lists %d members", len(st.Devices))
	}
}

// A removal handed to the service is offered to the device it removes first;
// here that device is not running, so the offer fails, and says so.
func TestServiceInformOffersARemovalToTheRemoved(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	f := newServiceFixtureWith(t, func(o *Options) {
		o.Logf = func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			lines = append(lines, fmt.Sprintf(format, args...))
		}
	})
	auth, _ := f.nw.authorityFor(t)
	victim := f.nw.devices[1].record.Identity
	removal := f.nw.removeNode(t, auth, victim)
	body, err := removal.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdInform, Records: [][]byte{body}}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range lines {
		if strings.Contains(l, "the change that ends its membership") && strings.Contains(l, victim.ShortString()) {
			return
		}
	}
	t.Fatalf("the removed device was not offered its removal:\n%s", strings.Join(lines, "\n"))
}

// A device moved at once moves onto its new address as the move applies, not
// at the next look at its addresses.
func TestAMovedDeviceMovesOntoItsNewAddressAtOnce(t *testing.T) {
	f := newServiceFixture(t, true)
	before := f.s.Mesh()
	auth, _ := f.nw.authorityFor(t)
	self := f.nw.devices[0].record.Identity
	move, err := auth.Builder().RenumberNode(self, netip.MustParseAddr("198.18.0.99"), types.RetireAtOnce)
	if err != nil {
		t.Fatal(err)
	}
	if err := move.SignUnder(f.nw.admin, auth.State().Schema()); err != nil {
		t.Fatal(err)
	}
	body, err := move.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdInform, Records: [][]byte{body}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(rotationCheckInterval / 2)
	for {
		if m := f.s.Mesh(); m == before && !m.addrsMoved() &&
			slices.Contains(m.heldAddrs(), netip.MustParsePrefix("198.18.0.99/32")) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the moved device did not move onto its new address before its next look")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAServiceInProcessAnswersThroughItsPipeAlone(t *testing.T) {
	nw := newNetwork(t, 2)
	home := socketDir(t)
	writeDevice(t, home, nw.devices[0])
	s, err := NewService(ServiceOptions{Home: home, InProcess: true, Logf: safeLogf(t, ""),
		Mesh: Options{DisableDiscovery: true, DisableDHT: true}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); s.Close() })
	if _, err := os.Lstat(ipc.SocketPath(home)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a service in process made %s: %v", ipc.SocketPath(home), err)
	}
	resp, err := ipc.CallVia(s.Pipe, ipc.Request{Command: ipc.CmdStatus})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Status.CanOperate || resp.Status.Self != nw.devices[0].record.Identity {
		t.Errorf("status through the pipe: CanOperate=%v Self=%v", resp.Status.CanOperate, resp.Status.Self)
	}
	if _, err := ipc.CallVia(s.Pipe, ipc.Request{Command: ipc.CmdPing, Ping: nw.devices[1].record.Identity}); err == nil ||
		err.Error() != errNoNetwork.Error() {
		t.Errorf("a ping outside any network: %v", err)
	}
	s.Close()
	if _, err := s.Pipe(); err == nil {
		t.Error("a closed service still opened a pipe")
	}
}

func TestCallsInProcessAreNotHeldToOneUsersShare(t *testing.T) {
	nw := newNetwork(t, 2)
	home := socketDir(t)
	writeDevice(t, home, nw.devices[0])
	s, err := NewService(ServiceOptions{Home: home, InProcess: true, Logf: safeLogf(t, ""),
		Mesh: Options{DisableDiscovery: true, DisableDHT: true}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); s.Close() })
	// Calls that have not sent their request yet hold their slots, as a join
	// waiting for votes and pings waiting for answers do.
	for range maxOperatorsPerUser + 2 {
		c, err := s.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
	}
	if _, err := ipc.CallVia(s.Pipe, ipc.Request{Command: ipc.CmdStatus}); err != nil {
		t.Errorf("a status call beside %d others: %v", maxOperatorsPerUser+2, err)
	}
}

// The CLI checks the disable record against the log it rebuilds, so the reply
// of records off the chain carries it whatever else fills its bound.
func TestTheDisableRecordComesFirstOffTheChain(t *testing.T) {
	f := newServiceFixture(t, true)
	mesh := f.s.Mesh()
	mesh.authMu.Lock()
	b := mesh.authority.Builder()
	mesh.authMu.Unlock()
	var lost types.Hash
	var admissions []types.AUM
	for i, name := range []string{"one", "two"} {
		dev := newDevice(t, name, netip.AddrFrom4([4]byte{100, 64, 0, byte(50 + i)}))
		rec, err := b.AddNode(dev.record, f.nw.sealer())
		if err != nil {
			t.Fatal(err)
		}
		if err := rec.SignUnder(f.nw.admin, mesh.authority.State().Schema()); err != nil {
			t.Fatal(err)
		}
		admissions = append(admissions, rec)
	}
	if err := mesh.Inform(admissions); err != nil {
		t.Fatal(err)
	}
	mesh.authMu.Lock()
	head := mesh.authority.Head()
	mesh.authMu.Unlock()
	for _, r := range admissions {
		if r.Hash() != head {
			lost = r.Hash()
		}
	}
	// Hashed after the lost admission, so that a reply in hash order alone
	// would leave it out.
	var aum types.AUM
	for i := uint32(1); ; i++ {
		parent := types.Hash{7}
		binary.BigEndian.PutUint32(parent[1:], i)
		aum = types.AUM{Kind: types.KindDisable, Prev: &parent, Secret: &f.nw.disablement}
		if aum.Hash().Compare(lost) > 0 {
			break
		}
	}
	if err := mesh.Inform([]types.AUM{aum}); err != nil {
		t.Fatal(err)
	}
	chain, err := f.s.chain()
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.s.orphans(chain, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("%d records off the chain, want 1", len(out))
	}
	if got, err := types.DecodeAUM(out[0]); err != nil || got.Hash() != aum.Hash() {
		t.Fatalf("the first record off the chain is not the disable record: %v", err)
	}
}

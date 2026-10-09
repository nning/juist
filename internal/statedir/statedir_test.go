package statedir

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/types"
)

// lockExclusive takes home's lock the way juistd does.
func lockExclusive(t *testing.T, home string) (*os.File, error) {
	t.Helper()
	f, err := OpenLock(filepath.Join(home, LockName))
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func TestADaemonAndACLIHoldTheHomeInTurn(t *testing.T) {
	home := t.TempDir()
	if HomeInUse(home) {
		t.Fatal("a home with no lock file is in use")
	}

	daemon, err := lockExclusive(t, home)
	if err != nil {
		t.Fatal(err)
	}
	if !HomeInUse(home) {
		t.Error("a running daemon's home is not in use")
	}
	if _, err := ShareHome(home); !errors.Is(err, ErrHomeInUse) {
		t.Errorf("sharing a running daemon's home: %v, want ErrHomeInUse", err)
	}
	daemon.Close()

	cli, err := ShareHome(home)
	if err != nil {
		t.Fatalf("sharing an idle home: %v", err)
	}
	if HomeInUse(home) {
		t.Error("a home the CLI shares reads as a running daemon's")
	}
	if second, err := ShareHome(home); err != nil {
		t.Errorf("a second CLI cannot share the home: %v", err)
	} else {
		second.Close()
	}
	if _, err := lockExclusive(t, home); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Errorf("a daemon took a home the CLI holds: %v", err)
	}
	cli.Close()
	if d, err := lockExclusive(t, home); err != nil {
		t.Errorf("a daemon cannot take the home once the CLI let go: %v", err)
	} else {
		d.Close()
	}
}

func TestTheLockIsARegularFile(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "target"), link); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenLock(link); err == nil {
		f.Close()
		t.Error("a symlink was opened as the lock")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenLock(fifo); err == nil {
		f.Close()
		t.Error("a FIFO was opened as the lock")
	}
}

func TestWriteFilePrivateReplacesWholeAndOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	old := unix.Umask(0)
	defer unix.Umask(old)
	if err := os.WriteFile(path, []byte("an older and longer content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFilePrivate(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "new" {
		t.Fatalf("read back %q, %v", b, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("written with mode %o, want 600", perm)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("the write left %d entries behind, want only the file", len(entries))
	}
}

func TestSeedHintsKeepsOnlyWhatVerifies(t *testing.T) {
	home := t.TempDir()
	id, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	good := gossip.Endpoint{Identity: id.Public(), Disco: gossip.DiscoKey{1}, GossipPort: 41644, Seq: 1,
		Addrs: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41643")}}
	if err := good.Sign(id); err != nil {
		t.Fatal(err)
	}
	forged := good
	forged.Addrs = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:41643")}
	goodB, err := good.Encode()
	if err != nil {
		t.Fatal(err)
	}
	forgedB, err := forged.Encode()
	if err != nil {
		t.Fatal(err)
	}

	lease := func(issued uint64) []byte {
		l := types.Lease{Network: types.Hash{1}, Head: types.Hash{2}, Issued: issued}
		if err := l.Sign(id); err != nil {
			t.Fatal(err)
		}
		b, err := l.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	if err := SeedHints(home, [][]byte{{0xff}, forgedB, goodB}, [][]byte{{0xff}, lease(1), lease(2)}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(EndpointCachePath(home))
	if err != nil {
		t.Fatal(err)
	}
	var held []gossip.Endpoint
	if err := gossip.DecodeCachedEndpoints(b, &held, nil); err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || !held[0].SameAs(&good) {
		t.Errorf("the cache holds %v, want only the verified announcement", held)
	}
	b, err = os.ReadFile(LeasePath(home))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeLeaseFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("the lease file holds %d leases, want the newest one", len(raw))
	}
	if l, err := types.DecodeLease(raw[0]); err != nil || l.Issued != 2 {
		t.Errorf("the lease kept is %+v, %v; want the one issued at 2", l, err)
	}

	empty := t.TempDir()
	if err := SeedHints(empty, [][]byte{forgedB}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(EndpointCachePath(empty)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("hints with nothing that verifies left a cache: %v", err)
	}
}

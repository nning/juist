package daemon

import (
	"os"
	"slices"
	"testing"
	"time"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// A network at the schema before the cut-over gathers every member's signing
// key from their announcements, cuts over while one member sleeps, and goes
// on: the two awake reach each other on ML-DSA-signed announcements, and the
// sleeper, back, catches up across the cut-over and the epoch it bumped.
func TestAMemberAsleepAcrossTheCutOverCatchesUp(t *testing.T) {
	nw := newNetworkMutated(t, 3, func(nw *network) {
		nw.schema = types.SchemaSigning
		nw.devices[0].record.Roles = []types.Role{types.RoleAdmin}
	})
	m := &mesh{t: t, nw: nw, hub: &lanHub{}}
	kept := []*persisted{keep(t, nw), keep(t, nw), keep(t, nw)}
	clock := &passing{}
	for i := range 3 {
		m.nodes = append(m.nodes, m.startKept(t, i, nw.devices[i], kept[i], clock))
	}
	admin, awake, sleeper := m.nodes[0], m.nodes[1], m.nodes[2]
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	claims := func() []types.MemberKey {
		var out []types.MemberKey
		for _, n := range m.nodes {
			e, ok := admin.d.endpoints.Get(n.id())
			if n == admin {
				e, ok = admin.d.Announcement()
			}
			if ok && e.Signing != nil {
				out = append(out, types.MemberKey{Identity: n.id(), Key: e.Signing.Key, Endorsement: e.Signing.Endorsement})
			}
		}
		return out
	}
	waitFor(t, 30*time.Second, "every member to announce its signing key", func() bool { return len(claims()) == 3 })
	waitFor(t, 10*time.Second, "the sleeper to cache its peers' addresses", func() bool {
		b, err := os.ReadFile(kept[2].cache)
		return err == nil && len(b) > 0
	})
	m.apply(t, admin, func(b *log.Builder) (types.AUM, error) {
		return b.SetAdminSigning(types.MemberKey{Identity: nw.admin.Public(), Key: nw.admin.SigningKey(),
			Endorsement: *nw.admin.Endorsement()})
	})
	sleeper.halt()

	keys := claims()
	slices.SortFunc(keys, func(x, y types.MemberKey) int { return x.Identity.Compare(y.Identity) })
	cut, err := admin.auth.Builder().SetSigningKeys(keys, nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := cut.SignUnder(nw.admin, admin.auth.State().Schema()); err != nil {
		t.Fatal(err)
	}
	if err := admin.d.Inform([]types.AUM{cut}); err != nil {
		t.Fatalf("the cut-over: %v", err)
	}
	waitFor(t, 30*time.Second, "the member awake to cut over", func() bool {
		return awake.d.Status().Schema == types.SchemaMLDSA
	})
	waitFor(t, 30*time.Second, "the two awake to hold each other's ML-DSA-signed announcements", func() bool {
		e, ok := admin.d.endpoints.Get(awake.id())
		f, ok2 := awake.d.endpoints.Get(admin.id())
		return ok && ok2 && e.MLDSA != nil && f.MLDSA != nil && !admin.d.endpoints.IsHint(awake.id()) &&
			!awake.d.endpoints.IsHint(admin.id())
	})
	if !pingUntil(awake, admin.overlayV4(), 20*time.Second) {
		t.Fatal("past the cut-over the two awake do not reach each other")
	}

	clock.advance(time.Hour)
	sleeper = m.startKept(t, 2, nw.devices[2], kept[2], clock)
	m.nodes[2] = sleeper
	head := admin.d.Status()
	waitFor(t, 60*time.Second, "the sleeper to catch up across the cut-over", func() bool {
		st := sleeper.d.Status()
		return st.Schema == types.SchemaMLDSA && st.Head == head.Head && st.Epoch == head.Epoch
	})
	waitFor(t, 30*time.Second, "the three to hold each other as peers again", m.converged)
	if !pingUntil(sleeper, admin.overlayV4(), 20*time.Second) {
		t.Fatal("the member that slept across the cut-over does not reach the admin device")
	}
}

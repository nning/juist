package policy

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// NetworkOf is state's policy against its members live at now, Unix seconds.
func NetworkOf(state *log.State, now int64) *Network {
	n := &Network{Policy: state.Policy()}
	for _, rec := range state.Nodes() {
		if rec.Expired(now) {
			continue
		}
		var addrs []netip.Addr
		for _, a := range state.Addrs(rec.Identity, now) {
			addrs = append(addrs, a.Addr())
		}
		var names []Name
		for _, p := range rec.Published {
			if p.Public == 0 {
				names = append(names, Name{Label: p.Label, Port: p.Port, Members: p.Members})
			}
		}
		n.Members = append(n.Members, Member{
			ID:        rec.Identity,
			Addrs:     addrs,
			Exit:      rec.HasRole(types.RoleExit),
			Subnets:   rec.SubnetRoutes(),
			Carrier:   rec.HasRole(types.RoleRelayCapable) || rec.HasRole(types.RoleAdmin),
			Service:   rec.HasRole(types.RoleService),
			Ingress:   rec.HasRole(types.RoleIngress),
			Publishes: len(rec.Published) > 0 || rec.HasRole(types.RolePublish),
			Names:     names,
		})
	}
	return n
}

// Members resolves a member by its name, regardless of case, or by its
// whole key.
func Members(state *log.State) Resolver {
	return func(name string) (types.Identity, error) {
		var found []types.NodeRecord
		for _, n := range state.Nodes() {
			if strings.EqualFold(n.Name, name) || n.Identity.String() == name {
				found = append(found, n)
			}
		}
		switch len(found) {
		case 1:
			return found[0].Identity, nil
		case 0:
			return types.Identity{}, fmt.Errorf("no device %q in %q\nhint: juist log says whether it was renamed or removed", name, state.Network())
		}
		return types.Identity{}, fmt.Errorf("%q names %d devices; name one by its key", name, len(found))
	}
}

// Names names members as state does.
func Names(state *log.State) Namer {
	return func(id types.Identity) string {
		if n, ok := state.Node(id); ok {
			return n.Name
		}
		return ""
	}
}

// Detached resolves every name to a key of its own, and names it back, for
// a policy read without the log.
func Detached() (Resolver, Namer) {
	names := map[types.Identity]string{}
	resolve := func(name string) (types.Identity, error) {
		if id, err := types.ParseIdentity(name); err == nil {
			return id, nil
		}
		id := types.Identity(sha256.Sum256([]byte(types.LabelPolicyDetached + "\x00" + name)))
		names[id] = name
		return id, nil
	}
	return resolve, func(id types.Identity) string { return names[id] }
}

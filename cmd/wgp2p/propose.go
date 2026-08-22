package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/nning/wg-p2p/trust/log"
	"github.com/nning/wg-p2p/types"
)

const proposeUsage = `Usage: wgp2p propose <record> [flags]

Builds an unsigned record against the current head and writes it to stdout (or
-o FILE). The record is checked against the current state as it is built, so a
record that could never apply is refused before a signing ceremony is spent on
it. Nothing is applied: collect signatures with "wgp2p sign", then "wgp2p apply".

Records:
  add-node        Admit a member
  remove-node     Revoke a member
  set-routes      Replace a member's roles and advertised routes
  rotate-key      Replace this device's WireGuard and encryption keys
  rotate-identity Replace this device's identity key
  add-admin       Add an admin signing key
  remove-admin    Remove an admin signing key
  set-quorum      Change the vote threshold
  epoch-bump      Rotate the group secret without changing membership
  checkpoint      State the current state, for compaction and bootstrapping
`

func cmdPropose(h *home, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, proposeUsage)
		return errSilent
	}
	kind, rest := args[0], args[1:]
	if kind == "-h" || kind == "--help" || kind == "help" {
		fmt.Print(proposeUsage)
		return nil
	}

	_, auth, err := h.openAuthority()
	if err != nil {
		return err
	}
	b := auth.Builder()

	fs := flag.NewFlagSet("wgp2p propose "+kind, flag.ContinueOnError)
	out := fs.String("o", "", "write the record here instead of stdout")

	var aum types.AUM
	switch kind {
	case "add-node":
		name := fs.String("name", "", "human label for the member")
		identity := fs.String("identity", "", "the device's identity key (nid:…)")
		wg := fs.String("wg", "", "the device's WireGuard public key (wg:…)")
		x := fs.String("x25519", "", "the device's X25519 key (x25519:…)")
		m := fs.String("mlkem", "", "the device's ML-KEM key (mlkem:…)")
		v4 := fs.String("v4", "", "optional overlay IPv4 address inside "+types.CGNAT.String())
		roles := fs.String("roles", "", "comma-separated roles to grant")
		routes := fs.String("routes", "", "comma-separated prefixes the member may forward for")
		if err := fs.Parse(rest); err != nil {
			return errSilent
		}
		rec, err := buildNodeRecord(*name, *identity, *wg, *x, *m, *v4, *roles, *routes)
		if err != nil {
			return err
		}
		aum, err = b.AddNode(rec, sealer())
		if err != nil {
			return err
		}

	case "remove-node":
		identity := fs.String("identity", "", "the member's identity key (nid:…)")
		if err := fs.Parse(rest); err != nil {
			return errSilent
		}
		id, err := types.ParseIdentity(*identity)
		if err != nil {
			return err
		}
		if aum, err = b.RemoveNode(id, sealer()); err != nil {
			return err
		}

	case "set-routes":
		identity := fs.String("identity", "", "the member's identity key (nid:…)")
		roles := fs.String("roles", "", "comma-separated roles; empty withdraws all")
		routes := fs.String("routes", "", "comma-separated prefixes; empty withdraws all")
		if err := fs.Parse(rest); err != nil {
			return errSilent
		}
		id, err := types.ParseIdentity(*identity)
		if err != nil {
			return err
		}
		roleList, err := parseRoles(*roles)
		if err != nil {
			return err
		}
		routeList, err := parseRoutes(*routes)
		if err != nil {
			return err
		}
		if aum, err = b.SetNodeRoutes(id, roleList, routeList); err != nil {
			return err
		}

	case "rotate-key":
		if err := fs.Parse(rest); err != nil {
			return errSilent
		}
		if aum, err = h.proposeRotateKey(b); err != nil {
			return err
		}

	case "rotate-identity":
		if err := fs.Parse(rest); err != nil {
			return errSilent
		}
		if aum, err = h.proposeRotateIdentity(b); err != nil {
			return err
		}

	case "add-admin":
		name := fs.String("name", "", "human label for the key")
		key := fs.String("key", "", "the admin public key (nid:…)")
		votes := fs.Uint("votes", 1, "vote weight")
		if err := fs.Parse(rest); err != nil {
			return errSilent
		}
		id, err := types.ParseIdentity(*key)
		if err != nil {
			return err
		}
		if aum, err = b.AddAdminKey(types.AdminKey{
			Public: id, Votes: uint32(*votes), Name: *name,
		}); err != nil {
			return err
		}

	case "remove-admin":
		key := fs.String("key", "", "the admin public key (nid:…)")
		if err := fs.Parse(rest); err != nil {
			return errSilent
		}
		id, err := types.ParseIdentity(*key)
		if err != nil {
			return err
		}
		if aum, err = b.RemoveAdminKey(id); err != nil {
			return err
		}

	case "set-quorum":
		k := fs.Uint("k", 0, "the new vote threshold")
		if err := fs.Parse(rest); err != nil {
			return errSilent
		}
		if aum, err = b.SetQuorum(uint32(*k)); err != nil {
			return err
		}

	case "epoch-bump":
		if err := fs.Parse(rest); err != nil {
			return errSilent
		}
		if aum, err = b.EpochBump(sealer()); err != nil {
			return err
		}

	case "checkpoint":
		if err := fs.Parse(rest); err != nil {
			return errSilent
		}
		if aum, err = b.Checkpoint(); err != nil {
			return err
		}

	default:
		fmt.Fprint(os.Stderr, proposeUsage)
		return fmt.Errorf("unknown record %q", kind)
	}

	if *out != "" {
		if err := writeRecordFile(*out, &aum); err != nil {
			return err
		}
		status := auth.State().SignatureStatus(&aum)
		fmt.Fprintf(os.Stderr, "wrote %v record to %s; needs %d more vote weight\n",
			aum.Kind, *out, missing(status))
		return nil
	}
	text, err := encodeRecord(&aum)
	if err != nil {
		return err
	}
	fmt.Print(text)
	return nil
}

// proposeRotateKey rotates every rotatable key this device holds.
//
// All of them, not a subset, and all generated here: a record naming a public
// key whose private half this device does not hold would be applied happily by
// the log and would leave the device unable to handshake or to read the group
// secret.
func (h *home) proposeRotateKey(b *log.Builder) (types.AUM, error) {
	staged, err := h.rotatedKeys()
	if err != nil {
		return types.AUM{}, err
	}
	aum, err := b.RotateNodeKey(staged.identity.Public(), staged.public, sealer())
	if err != nil {
		return types.AUM{}, err
	}
	return aum, h.stageNodeKeys(staged)
}

func (h *home) proposeRotateIdentity(b *log.Builder) (types.AUM, error) {
	cur, err := h.nodeKeys()
	if err != nil {
		return types.AUM{}, fmt.Errorf("reading this device's keys: %w", err)
	}
	staged, err := h.rotatedIdentity()
	if err != nil {
		return types.AUM{}, err
	}
	aum, err := b.RotateIdentity(cur.identity.Public(), staged.identity.Public(), sealer())
	if err != nil {
		return types.AUM{}, err
	}
	return aum, h.stageNodeKeys(staged)
}

func buildNodeRecord(name, identity, wg, x, m, v4, roles, routes string) (types.NodeRecord, error) {
	var rec types.NodeRecord
	var err error
	if rec.Identity, err = types.ParseIdentity(identity); err != nil {
		return rec, err
	}
	if rec.WireGuard, err = types.ParseWGKey(wg); err != nil {
		return rec, err
	}
	if rec.X25519, err = types.ParseX25519Key(x); err != nil {
		return rec, err
	}
	if rec.MLKEM, err = types.ParseMLKEMKey(m); err != nil {
		return rec, err
	}
	rec.Name = name
	if v4 != "" {
		addr, err := netip.ParseAddr(v4)
		if err != nil {
			return rec, fmt.Errorf("-v4: %w", err)
		}
		rec.V4 = &addr
	}
	if rec.Roles, err = parseRoles(roles); err != nil {
		return rec, err
	}
	if rec.Routes, err = parseRoutes(routes); err != nil {
		return rec, err
	}
	return rec, nil
}

func parseRoles(s string) ([]types.Role, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []types.Role
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, types.Role(part))
	}
	return out, nil
}

func parseRoutes(s string) ([]netip.Prefix, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", part, err)
		}
		out = append(out, pfx)
	}
	return out, nil
}

func missing(st log.SignatureStatus) uint32 {
	if st.Votes >= st.Quorum {
		return 0
	}
	return st.Quorum - st.Votes
}

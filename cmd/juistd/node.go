package main

import (
	"fmt"
	"path/filepath"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// node is what the daemon needs out of a state directory: the log, and the key
// material that makes this device a member of it.
//
// Notably absent: anything from admins/. The daemon does not read admin keys
// and could not use them if it did — every record it applies has to arrive
// already signed (docs/04-architecture.md, key custody).
type node struct {
	authority *log.Authority
	storage   *store.Dir
	identity  types.PrivateIdentity
	recipient *secrets.PrivateKeys
	wireguard [32]byte
}

// openNode loads a state directory that has already been enrolled.
//
// Every failure here is reported with what to do about it, because all of them
// are the same situation from the operator's side — this device is not set up
// yet — and they need different answers.
func openNode(home string) (*node, error) {
	if err := keys.RefuseSharedWritable(home); err != nil {
		return nil, err
	}
	k, err := keys.LoadNode(filepath.Join(home, keys.NodeKeysFile))
	if keys.Missing(err) {
		return nil, fmt.Errorf(
			"%s holds no node keys; this device has not been set up. Run: juist -home %s key -create",
			home, home)
	}
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(home, keys.LogDir))
	if err != nil {
		return nil, err
	}
	if _, ok, err := st.Anchor(); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf(
			"%s holds no network; this device has not been enrolled. Give an admin the output of "+
				"\"juist -home %s key\"; once they have applied the record that admits this device, "+
				"copy their log directory to %s. The record itself cannot be applied here — only a "+
				"genesis record can create a log, and this device is joining one that already exists",
			home, home, filepath.Join(home, keys.LogDir))
	}
	auth, err := log.Open(st)
	if err != nil {
		return nil, err
	}
	// A rotation applied anywhere but this device arrives here as log records
	// over gossip, with no CLI involved: the staged key file sits unpromoted
	// while the log names the keys in it, and every tunnel and the group
	// secret both fail against the old ones. The daemon reports that as
	// StaleKeys and says "restart juistd to pick up the promoted key file" —
	// which is only true if a restart is what promotes them. This is that.
	if promoted, err := keys.MaybePromoteStaged(home, auth.State().Node); err != nil {
		return nil, err
	} else if promoted != nil {
		fmt.Printf("promoted this device's staged keys; the log names them\n")
		k = promoted
	}
	return &node{
		authority: auth,
		storage:   st,
		identity:  k.Identity,
		recipient: k.Recipient,
		wireguard: k.WireGuardPrivate(),
	}, nil
}

// Package changelog says a network's changes as juist log lists them.
package changelog

import (
	"cmp"
	"fmt"

	"github.com/nning/juist/types"
)

// KindName is what a person calls a change of kind k.
func KindName(k types.Kind) string {
	if name, ok := kindNames[k]; ok {
		return name
	}
	return k.String()
}

var kindNames = map[types.Kind]string{
	types.KindGenesis:           "network creation",
	types.KindAddNode:           "device admission",
	types.KindRemoveNode:        "device removal",
	types.KindSetNodeRoutes:     "change of a device's roles or subnets",
	types.KindRotateNodeKey:     "key rotation",
	types.KindRotateIdentity:    "identity rotation",
	types.KindAddAdminKey:       "new admin key",
	types.KindRemoveAdminKey:    "admin key removal",
	types.KindSetQuorum:         "change of the approval threshold",
	types.KindCheckpoint:        "checkpoint",
	types.KindEpochBump:         "group secret rotation",
	types.KindSchemaUpgrade:     "schema upgrade",
	types.KindSetHolder:         "change of how many of an admin's keys must sign",
	types.KindSetVouchers:       "change of how many vouchers must confirm",
	types.KindRenumberNetwork:   "renumbering of the network",
	types.KindRenumberNode:      "renumbering of a device",
	types.KindRetireAddresses:   "retirement of old addresses",
	types.KindRenameNetwork:     "renaming of the network",
	types.KindSetAdminRecipient: "encryption key of an admin key",
	types.KindSetNodeNames:      "change of the public names a device answers for",
	types.KindSetDomain:         "change of the network's public domain",
	types.KindSetPublished:      "change of the names a device publishes",
	types.KindRenameNode:        "renaming of a device",
}

// An Entry is one change: what it did, who approved it, and its hash.
type Entry struct {
	What    string
	Signers []string
	Hash    types.Hash
}

// keyPerson is who holds an admin key.
func keyPerson(k types.AdminKey) string { return cmp.Or(k.Holder, k.Name) }

// Of lists chain's changes, anchor first, naming devices and admins as the
// chain and admins, the current admin keys, name them.
func Of(chain []types.AUM, admins []types.AdminKey) []Entry {
	// Names from the whole chain, so a removed device is still named in the
	// record that removed it.
	names := map[types.Identity]string{}
	for _, aum := range chain {
		if aum.Node != nil && aum.Node.Name != "" {
			names[aum.Node.Identity] = aum.Node.Name
		}
		if aum.Admin != nil && keyPerson(*aum.Admin) != "" {
			names[aum.Admin.Public] = keyPerson(*aum.Admin)
		}
		if aum.NodeName != nil && aum.Subject != nil {
			names[*aum.Subject] = *aum.NodeName
		}
		// A device's new identity key signs its own rotation.
		if aum.NewIdentity != nil && aum.Subject != nil {
			if n, ok := names[*aum.Subject]; ok {
				names[*aum.NewIdentity] = n
			}
		}
		if aum.State != nil {
			for _, n := range aum.State.Nodes {
				if n.Name != "" {
					names[n.Identity] = n.Name
				}
			}
			for _, k := range aum.State.Admins {
				if keyPerson(k) != "" {
					names[k.Public] = keyPerson(k)
				}
			}
		}
	}
	for _, k := range admins {
		if keyPerson(k) != "" {
			names[k.Public] = keyPerson(k)
		}
	}
	nameOf := func(id types.Identity) string {
		if n, ok := names[id]; ok {
			return n
		}
		return id.ShortString()
	}
	// A device's name until it was renamed, for the record renaming it.
	named := map[types.Identity]string{}
	out := make([]Entry, 0, len(chain))
	for _, aum := range chain {
		// One name per signer, with how many of their keys signed: two keys
		// of one admin are one approval.
		var signers []string
		keysOf := map[string]int{}
		for _, sig := range aum.Signatures {
			n := nameOf(sig.KeyID)
			if keysOf[n] == 0 {
				signers = append(signers, n)
			}
			keysOf[n]++
		}
		for i, n := range signers {
			if k := keysOf[n]; k > 1 {
				signers[i] = fmt.Sprintf("%s (%d keys)", n, k)
			}
		}
		what := KindName(aum.Kind)
		switch {
		case aum.NodeName != nil:
			what += fmt.Sprintf(": %s to %q", cmp.Or(named[*aum.Subject], aum.Subject.ShortString()), *aum.NodeName)
		case aum.Node != nil:
			what += ": " + cmp.Or(aum.Node.Name, aum.Node.Identity.ShortString())
		case aum.Subject != nil:
			what += ": " + nameOf(*aum.Subject)
		case aum.Admin != nil:
			what += ": " + cmp.Or(aum.Admin.Holder, aum.Admin.Name)
		case aum.Holder != nil:
			what = "admin policy: " + aum.Holder.Name
		case aum.Network != nil:
			what += ": " + *aum.Network
		}
		switch {
		case aum.Node != nil:
			named[aum.Node.Identity] = aum.Node.Name
		case aum.NodeName != nil:
			named[*aum.Subject] = *aum.NodeName
		case aum.NewIdentity != nil:
			named[*aum.NewIdentity] = named[*aum.Subject]
		}
		if aum.State != nil {
			for _, n := range aum.State.Nodes {
				named[n.Identity] = n.Name
			}
		}
		out = append(out, Entry{What: what, Signers: signers, Hash: aum.Hash()})
	}
	return out
}

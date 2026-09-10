package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func cmdSign(h *home, args []string) error {
	fs := flag.NewFlagSet("juist sign", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: juist sign FILE...

Adds signatures from the local keystore to each record, in place: every admin
key in `+adminsDir+`/, and this device's identity key (live or staged) where the
record kind requires the subject's own signature.

Signing is not applying. A record gathers signatures as it travels between
admins — the whole point of k-of-n being that no machine holds k keys — and
"juist apply" is what commits one that has enough.
`)
	}
	if err := fs.Parse(args); err != nil {
		return parseResult(err)
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return errSilent
	}

	admins, err := h.adminKeys()
	if err != nil {
		return err
	}
	// Absent node keys are normal; a present but unloadable key file is a
	// fault to report, or signing omits the signature the record needs.
	node, nodeErr := h.nodeKeys()
	if nodeErr != nil && !keys.Missing(nodeErr) {
		return nodeErr
	}
	// A staged identity signs too: a rotate-identity record needs the new key,
	// which by definition is not yet the one in the log.
	staged, stagedErr := h.stagedNodeKeys()
	if stagedErr != nil && !keys.Missing(stagedErr) {
		return stagedErr
	}
	if len(admins) == 0 && nodeErr != nil && stagedErr != nil {
		return fmt.Errorf("this keystore holds no key that could sign anything; see: juist key -h")
	}

	// A keystore with no network is the air-gapped signing machine, which is
	// how a quorum becomes real. The cost is that nothing can check the record
	// belongs to the network the keys govern, so the operator is told. A store
	// that fails to open is still an error.
	st, auth, haveNetwork, err := h.openAuthorityAllowingNone()
	if err != nil {
		return err
	}
	if !haveNetwork {
		fmt.Fprintf(os.Stderr,
			"warning: this keystore holds no network, so records cannot be checked against one.\n"+
				"         Signing a record from another network makes it invalid for that network.\n")
	}

	for _, path := range fs.Args() {
		aum, err := readRecordFile(path)
		if err != nil {
			return err
		}
		// A signature by a key the target network does not trust does not
		// merely fail to count, it invalidates the record — so an operator
		// who signs someone else's record destroys it.
		stale := false
		if haveNetwork && aum.Kind != types.KindGenesis {
			if _, err := st.AUM(*aum.Prev); err != nil {
				return fmt.Errorf(
					"%s: its parent %v is not in this log, so this record belongs to another network "+
						"or to a chain this device has not caught up with. Signing it would make it "+
						"invalid for whoever's log it belongs to; sync first, or sign it on the right machine",
					path, *aum.Prev)
			}
			// Being in the log is not being the head: a record on an older
			// parent is judged against the state there, so if the admin set
			// has moved, a signature by a current admin invalidates it.
			stale = *aum.Prev != auth.Head()
			if stale {
				fmt.Fprintf(os.Stderr,
					"warning: %s is built on %v, which is no longer the head. It will be judged "+
						"against the state at that record, which this tool cannot evaluate, so the "+
						"status below is not reported. If the admin set has changed since, signing "+
						"it now may invalidate it — reissue it against the current head instead.\n",
					path, *aum.Prev)
			}
		}
		var added []types.Identity
		for _, key := range admins {
			if signIfWanted(&aum, key, auth, adminKey) {
				added = append(added, key.Public())
			}
		}
		if nodeErr == nil && signIfWanted(&aum, node.Identity, auth, nodeKey) {
			added = append(added, node.Identity.Public())
		}
		if stagedErr == nil && signIfWanted(&aum, staged.Identity, auth, nodeKey) {
			added = append(added, staged.Identity.Public())
		}
		if len(added) == 0 {
			fmt.Fprintf(os.Stderr, "%s: no local key can sign this %v record\n", path, aum.Kind)
			continue
		}
		if err := writeRecordFile(path, &aum); err != nil {
			return err
		}
		for _, id := range added {
			fmt.Printf("%s: signed by %v\n", path, id)
		}
		switch {
		case aum.Kind == types.KindGenesis:
			// A genesis is measured against the policy it declares, which is
			// the only thing available: the ceremony runs before the network
			// it creates exists, and on machines that will never hold its log.
			reportGenesisStatus(path, &aum)
		case stale:
			// Deliberately silent: see the warning above.
		case auth != nil:
			reportStatus(path, &aum, auth)
		}
	}
	return nil
}

// A keyRole says where a signing key came from, which decides what may be
// assumed about it when there is no log to check against.
type keyRole int

const (
	// adminKey is a key from admins/. Its whole purpose may be to sign for a
	// network this machine does not hold — that is what an air-gapped signing
	// machine is.
	adminKey keyRole = iota

	// nodeKey is this device's own identity, live or staged. It has exactly
	// one role in any record: being the subject of one that requires the
	// subject's own signature.
	nodeKey
)

// signIfWanted adds a signature only if the key has a role in this record: an
// untrusted signature is rejected outright rather than ignored, so signing
// where it is not wanted invalidates the record.
func signIfWanted(aum *types.AUM, key types.PrivateIdentity, auth *log.Authority, role keyRole) bool {
	id := key.Public()
	if aum.VerifySignature(id) {
		return false
	}
	if !wanted(aum, id, auth, role) {
		return false
	}
	return aum.Sign(key) == nil
}

func wanted(aum *types.AUM, id types.Identity, auth *log.Authority, role keyRole) bool {
	// Genesis is checked against the keys it declares, not against any earlier
	// state, so an admin key inside it is a valid signer even if no local log
	// lists it.
	if aum.Kind == types.KindGenesis && aum.State != nil {
		if _, ok := aum.State.Admin(id); ok {
			return true
		}
	}
	if self := log.SelfSigner(aum); self != nil && *self == id {
		return true
	}
	if auth == nil {
		// No log to check against. For an admin key that is unknowable, and
		// refusing would make an air-gapped key useless. A node key is not:
		// [log.SelfSigner] depends only on the record, so the check above is
		// complete — signing anyway would invalidate the enrollment record a
		// freshly created device's operator was sent.
		return role == adminKey
	}
	_, isAdmin := auth.State().Admin(id)
	return isAdmin
}

// reportGenesisStatus prints what a genesis record still needs, on a machine
// that has no network to check it against — which is every machine in the
// ceremony except the one that started it.
func reportGenesisStatus(path string, aum *types.AUM) {
	st, err := log.GenesisStatus(aum)
	if err != nil {
		fmt.Printf("%s: %v\n", path, err)
		return
	}
	switch {
	case len(st.Untrusted) > 0:
		fmt.Printf("%s: INVALID — signed by %v, which this genesis does not name as an admin key\n",
			path, st.Untrusted[0])
	case len(st.Invalid) > 0:
		fmt.Printf("%s: INVALID — the signature by %v does not verify\n", path, st.Invalid[0])
	case st.Votes < st.Quorum:
		fmt.Printf("%s: %d of %d vote weight; needs %d more before it creates a network\n",
			path, st.Votes, st.Quorum, missing(st))
	default:
		fmt.Printf("%s: authorized — create the network with: juist apply %s\n", path, path)
	}
}

// reportStatus prints what a record still needs, so the operator knows whether
// to pass it on or apply it.
func reportStatus(path string, aum *types.AUM, auth *log.Authority) {
	st := auth.State().SignatureStatus(aum)
	switch {
	case len(st.Untrusted) > 0:
		fmt.Printf("%s: INVALID — signed by %v, which this network does not trust for a %v record\n",
			path, st.Untrusted[0], aum.Kind)
	case len(st.Invalid) > 0:
		fmt.Printf("%s: INVALID — the signature by %v does not verify\n", path, st.Invalid[0])
	case st.Votes < st.Quorum:
		fmt.Printf("%s: %d of %d vote weight; needs %d more\n", path, st.Votes, st.Quorum, missing(st))
	case st.SelfSigner != nil && !st.SelfSigned:
		fmt.Printf("%s: quorum reached, still needs the signature of %v\n", path, *st.SelfSigner)
	default:
		fmt.Printf("%s: authorized — apply it with: juist apply %s\n", path, path)
	}
}

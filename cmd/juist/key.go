package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nning/juist/internal/keys"
)

func cmdKey(h *home, args []string) error {
	fs := flag.NewFlagSet("juist key", flag.ContinueOnError)
	create := fs.Bool("create", false, "generate this device's node keys if it has none")
	name := fs.String("name", "", "member name for this device, with -create (default: the hostname)")
	createAdmin := fs.String("create-admin", "", "generate an admin signing key under this name")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: juist key [-create [-name NAME]] [-create-admin NAME]

Prints this device's public keys and the local admin keys.

With -create, generates this device's node keys if it has none. The member
name defaults to the hostname; it is persisted with the keys and printed in
the enrollment command, but the admin may still change it when signing the
record.

With -create-admin NAME, generates an admin signing key. A keystore holding only
admin keys and no network is the right shape for a machine whose only job is to
sign: a k-of-n quorum means nothing if one machine holds k keys.

The node keys are what an admin needs in order to enroll this device; the
command to do it is printed ready to copy.
`)
	}
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	if *createAdmin != "" {
		// An admin key with no network of its own is the intended shape for a
		// device that only ever signs: docs/04-architecture.md keeps admin
		// keys out of the daemon, and a quorum only means anything if no
		// single machine holds k of them.
		priv, err := h.createAdminKey(*createAdmin)
		if err != nil {
			return err
		}
		fmt.Printf("admin key      %v\n", priv.Public())
	}

	k, err := h.nodeKeys()
	if err != nil && !keys.Missing(err) {
		// Reporting a broken key file as "no keys yet" would send the operator
		// to "juist key -create", which refuses to overwrite and leaves them
		// no closer to the mode or the truncation that is the actual problem.
		return err
	}
	if err != nil && *create {
		k, err = h.createNodeKeys(*name)
		if err != nil {
			return err
		}
	}
	if err == nil {
		if n := displayName(k); n != "" {
			fmt.Printf("node name      %s\n", n)
		}
		fmt.Printf("node identity  %v\n", k.Identity.Public())
		fmt.Printf("node wireguard %v\n", k.Public.WireGuard)
		fmt.Printf("node x25519    %v\n", k.Public.X25519)
		fmt.Printf("node mlkem     %v\n", k.Public.MLKEM)
		staged, serr := h.stagedNodeKeys()
		if serr != nil && !keys.Missing(serr) {
			return serr
		}
		if serr == nil {
			fmt.Printf("\nstaged for rotation (not live until the record is applied):\n")
			fmt.Printf("  identity     %v\n", staged.Identity.Public())
			fmt.Printf("  wireguard    %v\n", staged.Public.WireGuard)
		}
		fmt.Printf("\nto enroll this device, an admin runs:\n")
		if n := displayName(k); n != "" {
			fmt.Printf("  juist propose add-node -name %q \\\n", n)
		} else {
			fmt.Printf("  juist propose add-node -name NAME \\\n")
		}
		fmt.Printf("    -identity %v \\\n", k.Identity.Public())
		fmt.Printf("    -wg %v \\\n", k.Public.WireGuard)
		fmt.Printf("    -x25519 %v \\\n", k.Public.X25519)
		fmt.Printf("    -mlkem %v -o add.rec\n", k.Public.MLKEM)
	} else {
		fmt.Printf("this device has no keys yet; run: juist key -create\n")
	}

	admins, aerr := h.adminKeys()
	if aerr != nil {
		return aerr
	}
	for _, a := range admins {
		fmt.Printf("admin key      %v\n", a.Public())
	}
	if len(admins) == 0 {
		fmt.Printf("no admin keys in this keystore\n")
	}
	return nil
}

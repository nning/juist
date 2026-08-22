// Command wgp2p administers a wg-p2p membership log.
//
// M1 is the trust layer as a library, with no networking
// (docs/05-roadmap.md), so this tool does everything locally: it creates a
// network, builds records, collects signatures, verifies what it is given, and
// applies what is authorized. Moving records between machines is the operator's
// job for now — which is exactly the shape a quorum ceremony has anyway, since
// the point of k-of-n is that no single machine ever holds k keys.
//
// The signing ceremony looks like this:
//
//	wgp2p propose add-node -identity nid:… -wg wg:… -x25519 x25519:… -mlkem mlkem:… > add.rec
//	# hand add.rec to each admin in turn
//	wgp2p sign add.rec
//	wgp2p verify add.rec        # says what is still missing
//	wgp2p apply add.rec
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nning/wg-p2p/trust/log"
	"github.com/nning/wg-p2p/trust/store"
)

const usage = `wgp2p administers a wg-p2p membership log.

Usage:
  wgp2p [-home DIR] <command> [flags]

Commands:
  init      Create a network (the genesis ceremony)
  key       Show this device's public keys, for an admin to enroll
  propose   Build an unsigned record
  sign      Add signatures from the local keystore to a record
  verify    Verify the stored log, or a record against it
  apply     Apply an authorized record to the local log
  log show  Print the chain and the current state

Run "wgp2p <command> -h" for a command's flags.

The home directory defaults to $WGP2P_HOME, or ~/.config/wgp2p.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "wgp2p: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	global := flag.NewFlagSet("wgp2p", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	homePath := global.String("home", defaultHome(), "state directory")
	if err := global.Parse(args); err != nil {
		return errSilent
	}
	rest := global.Args()
	if len(rest) == 0 {
		global.Usage()
		return errSilent
	}

	h, err := openHome(*homePath)
	if err != nil {
		return err
	}
	cmd, cmdArgs := rest[0], rest[1:]
	switch cmd {
	case "init":
		return cmdInit(h, cmdArgs)
	case "key":
		return cmdKey(h, cmdArgs)
	case "propose":
		return cmdPropose(h, cmdArgs)
	case "sign":
		return cmdSign(h, cmdArgs)
	case "verify":
		return cmdVerify(h, cmdArgs)
	case "apply":
		return cmdApply(h, cmdArgs)
	case "log":
		return cmdLog(h, cmdArgs)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// errSilent reports a failure whose message has already been printed, so the
// exit code is set without repeating it.
var errSilent = silentError{}

type silentError struct{}

func (silentError) Error() string { return "" }

func defaultHome() string {
	if v := os.Getenv("WGP2P_HOME"); v != "" {
		return v
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "wgp2p")
	}
	return ".wgp2p"
}

// openAuthority opens the local log. It is deliberately not created on demand:
// a missing log means this device was never enrolled, and quietly creating one
// would hand the operator a second network with the same name.
func (h *home) openAuthority() (*store.Dir, *log.Authority, error) {
	st, auth, _, err := h.openAuthorityAllowingNone()
	if err != nil {
		return nil, nil, err
	}
	if auth == nil {
		return nil, nil, fmt.Errorf("%s holds no network; create one with \"wgp2p init\" or join one",
			h.join(logDir))
	}
	return st, auth, nil
}

// openAuthorityAllowingNone opens the log, treating "there is no network here"
// as a result rather than an error.
//
// Only "no network" is tolerated. A store that fails to open — a corrupt
// record, an unreadable file, a missing anchor — is an error, because treating
// it as "no network" is how a damaged log turns into a device that behaves as
// though it never had one.
func (h *home) openAuthorityAllowingNone() (*store.Dir, *log.Authority, bool, error) {
	st, err := store.Open(h.join(logDir))
	if err != nil {
		return nil, nil, false, err
	}
	if _, ok, err := st.Anchor(); err != nil {
		return nil, nil, false, err
	} else if !ok {
		return st, nil, false, nil
	}
	auth, err := log.Open(st)
	if err != nil {
		return nil, nil, false, err
	}
	return st, auth, true, nil
}

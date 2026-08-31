// Command juist administers a juist membership log.
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
//	juist propose add-node -identity nid:… -wg wg:… -x25519 x25519:… -mlkem mlkem:… > add.rec
//	# hand add.rec to each admin in turn
//	juist sign add.rec
//	juist verify add.rec        # says what is still missing
//	juist apply add.rec
//
// From M2 there is also a daemon, juistd, which owns the log on a member
// device and runs the mesh. When one is running, "juist apply" hands its
// records to it rather than writing underneath it, and "juist status" reports
// what it is doing.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
)

const usage = `juist administers a juist membership log.

Usage:
  juist [-home DIR] <command> [flags]

Commands:
  init      Create a network (the genesis ceremony)
  key       Show this device's public keys, for an admin to enroll
  propose   Build an unsigned record
  sign      Add signatures from the local keystore to a record
  status    Ask the local daemon what state it is in
  verify    Verify the stored log, or a record against it
  apply     Apply an authorized record to the local log
  log show  Print the chain and the current state

Run "juist <command> -h" for a command's flags.

The home directory defaults to $JUIST_HOME, or ~/.config/juist.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "juist: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	global := flag.NewFlagSet("juist", flag.ContinueOnError)
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
	case "status":
		return cmdStatus(h, cmdArgs)
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
	if v := os.Getenv("JUIST_HOME"); v != "" {
		return v
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "juist")
	}
	return ".juist"
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
		return nil, nil, fmt.Errorf("%s holds no network; create one with \"juist init\" or join one",
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

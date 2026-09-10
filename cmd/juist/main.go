// Command juist administers a juist membership log: it creates a network,
// builds records, collects signatures, verifies what it is given, and applies
// what is authorized. Moving records between machines is the operator's job,
// which is the shape a k-of-n ceremony has anyway.
//
//	juist propose add-node -identity nid:… -wg wg:… -x25519 x25519:… -mlkem mlkem:… > add.rec
//	# hand add.rec to each admin in turn
//	juist sign add.rec
//	juist verify add.rec        # says what is still missing
//	juist apply add.rec
//
// Where juistd is running it owns the log, so "apply" hands records to it
// rather than writing underneath it, and "status" reports what it is doing.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nning/juist/internal/keys"
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
	err := run(os.Args[1:])
	switch {
	case err == nil, errors.Is(err, errHelp):
		return
	case errors.Is(err, errSilent):
		os.Exit(1)
	default:
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
		return parseResult(err)
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
// exit code is set without repeating it. errHelp reports that help was asked
// for and given, which is what the caller wanted and so not a failure at all.
var (
	errSilent = silentError{}
	errHelp   = silentError{help: true}
)

type silentError struct{ help bool }

func (silentError) Error() string { return "" }

// parseResult classifies a flag-parsing error. The flag package has already
// printed the usage or the offending flag either way; what differs is whether
// the run succeeded.
func parseResult(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return errHelp
	}
	return errSilent
}

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
		if keys.NestedLog(h.join(logDir)) {
			return nil, nil, fmt.Errorf("%s holds no network, but %s does: a copied log landed "+
				"inside the existing directory. Move its contents up one level, or copy with "+
				"\"cp -r SRC/log/. %s/\"",
				h.join(logDir), h.join(logDir, keys.LogDir), h.join(logDir))
		}
		return nil, nil, fmt.Errorf("%s holds no network; create one with \"juist init\" or join one",
			h.join(logDir))
	}
	return st, auth, nil
}

// openAuthorityAllowingNone opens the log, treating "there is no network here"
// as a result rather than an error. Only that: a store that fails to open is
// an error, or a damaged log becomes a device that never had one.
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

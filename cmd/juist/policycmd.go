package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nning/juist/internal/policy"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func policyFamily() family {
	return family{name: "juist policy", intro: `Say which device may open what on which. Without a policy every device
may open anything on every other.`,
		subs: []subcommand{
			{name: "show", run: policyShow, forms: [][2]string{{"", "the network's policy"}}},
			{name: "edit", run: policyEdit, forms: [][2]string{{"edit", "change it in $EDITOR"}}},
			{name: "set", run: policySet, forms: [][2]string{{"set FILE", "make FILE the policy, - for standard input"}}},
			{name: "diff", run: policyDiff, forms: [][2]string{{"diff FILE", "how FILE differs from the policy"}}},
			{name: "check", run: policyCheck, forms: [][2]string{{"check FILE", "read FILE against the network, run its tests"}}},
			{name: "test", run: policyTest, forms: [][2]string{{"test from DEVICE to DEST ...", "whether the policy passes it, and by which rule"}}},
			{name: "fmt", run: policyFmt, forms: [][2]string{{"fmt [FILE...]", "print FILE in the policy's own form"}}},
			{name: "off", run: policyOff, forms: [][2]string{{"off", "withdraw it"}}},
		}, footer: `A policy passes what devices may open, in pf's words; the rest is refused:

  table <staff> { laptop, phone }
  pass from <staff> to nas proto tcp port 445
  pass from laptop to internet via vps

Relays and vouchers reach every device for juist's own traffic.`}
}

func cmdPolicy(a *app, args []string) error { return policyFamily().run(a, args) }

func policyShow(a *app, args []string) error {
	s := spec{name: "juist policy", args: "[SUBCOMMAND]", about: policyFamily().about()}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	p := state.Policy()
	switch {
	case p == nil:
		a.ok("no access policy: every device may open anything on every other")
	case len(p.Rules) == 0:
		fmt.Fprint(a.out, policy.Format(p, policy.Names(state)))
		a.warn("the access policy passes nothing")
	default:
		fmt.Fprint(a.out, policy.Format(p, policy.Names(state)))
	}
	return nil
}

func policySet(a *app, args []string) error {
	s := spec{name: "juist policy set", args: "FILE", min: 1, max: 1, about: `
Make FILE the network's access policy, once it reads against the network
and passes its tests; - reads standard input. It goes to the other admins
as other changes do where it needs their votes.`}
	fs := newFlags(s.name)
	yes := fs.Bool("yes", false, "do not ask")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	src, name, err := a.readPolicyFile(pos[0])
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	p, err := a.readPolicy(auth.State(), src, name)
	if err != nil {
		return err
	}
	return a.submitPolicy(auth, p, *yes)
}

func policyEdit(a *app, args []string) error {
	s := spec{name: "juist policy edit", about: `
Change the network's access policy in $VISUAL or $EDITOR, vi without
either, and set it once it reads and passes its tests.`}
	fs := newFlags(s.name)
	yes := fs.Bool("yes", false, "do not ask")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	if err := needsPolicySchema(state); err != nil {
		return err
	}
	was := ""
	if cur := state.Policy(); cur != nil {
		was = policy.Format(cur, policy.Names(state))
	}
	dir, err := os.MkdirTemp("", "juist-policy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "policy.conf")
	if err := os.WriteFile(path, []byte(was), 0o600); err != nil {
		return err
	}
	for {
		if err := a.edit(path); err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(b) == was {
			a.ok("unchanged: access policy")
			return nil
		}
		p, err := a.readPolicy(state, string(b), "policy")
		if err == nil {
			return a.submitPolicy(auth, p, *yes)
		}
		if !a.interactive {
			return err
		}
		fmt.Fprintf(a.errOut, "juist: %v\n", err)
		if again, err := a.confirm("edit again?"); err != nil || !again {
			a.ok("unchanged: access policy")
			return errSilent
		}
	}
}

func policyOff(a *app, args []string) error {
	s := spec{name: "juist policy off", about: `
Withdraw the network's access policy: every device may then open anything
on every other, as before it had one.`}
	fs := newFlags(s.name)
	yes := fs.Bool("yes", false, "do not ask")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	if auth.State().Policy() == nil {
		a.ok("unchanged: no access policy")
		return nil
	}
	if err := a.proceed(*yes, "every device may then open anything on every other; withdraw the access policy?"); err != nil {
		return err
	}
	aum, err := auth.Builder().SetPolicy(&types.Policy{})
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{aum: aum, file: "policy-off.rec",
		done: "access policy withdrawn: every device may open anything on every other"})
	return err
}

func policyDiff(a *app, args []string) error {
	s := spec{name: "juist policy diff", args: "FILE", min: 1, max: 1, about: `
Show how FILE differs from the network's access policy, both in the
policy's own form: - before a line only the policy has, + before one only
FILE has. Exits 1 where they differ.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	src, name, err := a.readPolicyFile(pos[0])
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	p, err := parsePolicy(state, src, name)
	if err != nil {
		return err
	}
	names := policy.Names(state)
	was := ""
	if cur := state.Policy(); cur != nil {
		was = policy.Format(cur, names)
	}
	is := policy.Format(p, names)
	if is == was {
		return nil
	}
	for _, l := range policy.Diff(was, is) {
		fmt.Fprintln(a.out, l)
	}
	return errSilent
}

func policyCheck(a *app, args []string) error {
	s := spec{name: "juist policy check", args: "FILE", min: 1, max: 1, about: `
Read FILE against the network, as juist policy set would, and run its
tests, setting nothing.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	src, name, err := a.readPolicyFile(pos[0])
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	p, err := a.readPolicy(auth.State(), src, name)
	if err != nil {
		return err
	}
	if len(p.Tests) == 0 {
		a.ok("%s: ok, no tests", name)
		return nil
	}
	a.ok("%s: passes its %s", name, count(len(p.Tests), "test"))
	return nil
}

func policyTest(a *app, args []string) error {
	s := spec{name: "juist policy test", args: "from DEVICE to DEST [proto P [port N]]", min: 4, max: -1, about: `
Say whether the network's access policy lets DEVICE open DEST, a device,
internet via DEVICE, an address or name NAME, a published name, and which
rule passes it; exits 1 where none does. It takes what a test line in a
policy takes.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	p, err := policy.Parse("test pass "+policy.Words(pos), policy.Members(state))
	if pe := (*policy.Error)(nil); errors.As(err, &pe) {
		return errors.New(pe.Msg)
	} else if err != nil {
		return err
	}
	t := p.Tests[0]
	n := policy.NetworkOf(state, a.now().Unix())
	if len(t.To.Names) == 1 {
		if _, _, ok := n.Publisher(t.To.Names[0]); !ok {
			return fmt.Errorf("%s is published on no device by TLS", nameUnder(t.To.Names[0], state.Domain()))
		}
	}
	names := policy.Names(state)
	passes, by := n.Explain(t)
	switch {
	case passes && by == nil:
		a.ok("passes: the network has no access policy")
		return nil
	case passes:
		a.ok("passes: %s", policy.RuleLine(*by, names))
		return nil
	}
	a.ok("refused: no rule passes it")
	if len(t.To.Nodes) == 1 {
		if own := n.View(t.From).Out[t.To.Nodes[0]].Own; len(own) > 0 {
			a.hint("%s may open on %s: %s", names(t.From), names(t.To.Nodes[0]), policy.PortsLine(own))
		}
	}
	return errSilent
}

func policyFmt(a *app, args []string) error {
	s := spec{name: "juist policy fmt", args: "[FILE...]", max: -1, anyNetwork: true, about: `
Print each FILE, standard input without one, in the policy's own form, as
juist policy prints it; no log is read. -w rewrites the files instead, and
-l lists those not in that form, failing if there are any.`}
	fs := newFlags(s.name)
	write := fs.Bool("write", false, "rewrite FILE in place")
	list := fs.Bool("list", false, "list files not in the policy's own form")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	switch {
	case *write && *list:
		return fmt.Errorf("-w or -l, not both\n%s", s.usage(fs))
	case len(pos) == 0 && (*write || *list), slices.Contains(pos, "-") && *write:
		return fmt.Errorf("-w and -l take files\n%s", s.usage(fs))
	case len(pos) == 0:
		pos = []string{"-"}
	}
	failed := false
	for _, f := range pos {
		src, name, err := a.readPolicyFile(f)
		var p *types.Policy
		resolve, names := policy.Detached()
		if err == nil {
			if p, err = policy.Parse(src, resolve); err != nil {
				err = lineError(name, err)
			}
		}
		if err != nil && !*list {
			return err
		}
		if err != nil {
			fmt.Fprintf(a.errOut, "juist: %v\n", err)
			failed = true
			continue
		}
		out := policy.Format(p, names)
		switch {
		case *list:
			if out != src {
				fmt.Fprintln(a.out, name)
				failed = true
			}
		case *write:
			if out != src {
				if err := writeFileKeepingMode(a.path(f), []byte(out)); err != nil {
					return err
				}
			}
		default:
			fmt.Fprint(a.out, out)
		}
	}
	if failed {
		return errSilent
	}
	return nil
}

// readPolicyFile reads a policy's text from path, standard input for -, and
// the name it is said by.
func (a *app) readPolicyFile(path string) (src, name string, err error) {
	if path == "-" {
		b, err := io.ReadAll(io.LimitReader(a.in, maxPolicyText+1))
		if err != nil {
			return "", "", err
		}
		if len(b) > maxPolicyText {
			return "", "", fmt.Errorf("standard input holds over %d bytes, more than any policy", maxPolicyText)
		}
		return string(b), "<stdin>", nil
	}
	f, err := os.Open(a.path(path))
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxPolicyText+1))
	if err != nil {
		return "", "", err
	}
	if len(b) > maxPolicyText {
		return "", "", fmt.Errorf("%s holds over %d bytes, more than any policy", path, maxPolicyText)
	}
	return string(b), path, nil
}

// maxPolicyText bounds what is read as a policy.
const maxPolicyText = 4 << 20

// parsePolicy reads src, called name, naming devices as state does.
func parsePolicy(state *log.State, src, name string) (*types.Policy, error) {
	if err := needsPolicySchema(state); err != nil {
		return nil, err
	}
	p, err := policy.Parse(src, policy.Members(state))
	if err != nil {
		return nil, lineError(name, err)
	}
	if p.Empty() {
		return nil, fmt.Errorf("%s holds no policy\nhint: juist policy off withdraws it", name)
	}
	return p, nil
}

// readPolicy is [parsePolicy], warning of what the policy names that it
// cannot mean, and refusing one that fails its tests.
func (a *app) readPolicy(state *log.State, src, name string) (*types.Policy, error) {
	p, err := parsePolicy(state, src, name)
	if err != nil {
		return nil, err
	}
	n := policy.NetworkOf(state, a.now().Unix())
	n.Policy = p
	names := policy.Names(state)
	for _, w := range n.Warnings(names) {
		a.warn("%s", w)
	}
	failed := n.Failures(names)
	lines := policy.TestLines(src)
	for _, f := range failed {
		at := name
		if f.Test < len(lines) {
			at = fmt.Sprintf("%s:%d", name, lines[f.Test])
		}
		fmt.Fprintf(a.errOut, "%s: fails: %s\n", at, f.Text)
	}
	if len(failed) > 0 {
		return nil, fmt.Errorf("%s fails %s", name, count(len(failed), "test"))
	}
	return p, nil
}

func needsPolicySchema(state *log.State) error {
	return nil
}

// lineError says err as FILE:LINE: where it is about a line.
func lineError(name string, err error) error {
	var pe *policy.Error
	if errors.As(err, &pe) {
		return fmt.Errorf("%s:%d: %s", name, pe.Line, pe.Msg)
	}
	return fmt.Errorf("%s: %w", name, err)
}

// submitPolicy makes p the network's policy.
func (a *app) submitPolicy(auth *log.Authority, p *types.Policy, yes bool) error {
	state := auth.State()
	if cur := state.Policy(); cur != nil && bytes.Equal(cur.Encode(), p.Encode()) {
		a.ok("unchanged: access policy")
		return nil
	}
	if len(p.Rules) == 0 {
		a.warn("the access policy passes nothing")
	}
	if state.Policy() == nil {
		if err := a.proceed(yes, "anything the policy does not pass is then refused; set it?"); err != nil {
			return err
		}
	}
	aum, err := auth.Builder().SetPolicy(p)
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{aum: aum, file: "policy.rec",
		done: fmt.Sprintf("access policy set: %s", count(len(p.Rules), "rule"))})
	return err
}

// policyLoss is what removing id takes from p, as the end of a sentence; ""
// where p does not name it.
func policyLoss(p *types.Policy, id types.Identity) string {
	named := false
	if p != nil {
		p.Nodes(func(n types.Identity) { named = named || n == id })
	}
	if !named {
		return ""
	}
	after := p.Rekeyed(id, nil)
	var lost []string
	if n := len(p.Rules) - len(after.Rules); n > 0 {
		lost = append(lost, count(n, "rule"))
	}
	if n := len(p.Tests) - len(after.Tests); n > 0 {
		lost = append(lost, count(n, "test"))
	}
	if len(lost) == 0 {
		return "; the access policy names it no more"
	}
	return "; the access policy names it no more, and loses " + strings.Join(lost, " and ")
}

// edit opens path in the operator's editor.
func (a *app) edit(path string) error {
	if a.editor != nil {
		return a.editor(path)
	}
	if !a.interactive {
		return errors.New("no terminal to edit in\nhint: juist policy set FILE")
	}
	editor := a.getenv("VISUAL")
	if editor == "" {
		editor = a.getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	cmd := exec.CommandContext(a.ctx, "/bin/sh", "-c", editor+` "$1"`, "sh", path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Fields(editor)[0], err)
	}
	return nil
}

// writeFileKeepingMode replaces path's content, keeping its mode.
func writeFileKeepingMode(path string, b []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".juist-policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

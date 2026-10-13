// Package cliflag holds juist's and juistd's options to one spelling: a long
// option is --name or --name=value, a one-letter one is -n, and -fy is -f -y.
// Go's flag package accepts either dash before any name, so without this
// "-home" would work and "--v" too. It also puts the dashes back into the
// flag package's errors, which always print one.
package cliflag

import (
	"errors"
	"flag"
	"fmt"
	"regexp"
	"strings"
)

// Short makes -c another name for the long option long, which must exist.
func Short(fs *flag.FlagSet, c byte, long string) {
	f := fs.Lookup(long)
	if f == nil || len(long) < 2 {
		panic("cliflag: no long option --" + long)
	}
	fs.Var(f.Value, string(c), f.Usage)
}

// IsSet reports whether the long option long was given, under either of its
// names. fs.Visit names only the one it was given as.
func IsSet(fs *flag.FlagSet, long string) bool {
	f := fs.Lookup(long)
	set := false
	fs.Visit(func(g *flag.Flag) { set = set || f != nil && g.Value == f.Value })
	return set
}

// Check refuses args that spell an option the wrong way, naming the right
// spelling, and options that do not exist, naming the closest that does. It
// returns args with each bundle of one-letter options, as -fy, written out as
// -f -y for fs.Parse. Everything after "--" is left alone.
func Check(fs *flag.FlagSet, args []string) ([]string, error) {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return append(out, args[i:]...), nil
		}
		if len(arg) < 2 || arg[0] != '-' {
			out = append(out, arg)
			continue
		}
		long := strings.HasPrefix(arg, "--")
		name, _, hasValue := strings.Cut(arg[1:], "=")
		if long {
			name = name[1:]
		}
		if name == "" || strings.HasPrefix(name, "-") {
			return nil, fmt.Errorf("%s is not an option", arg)
		}
		f := fs.Lookup(name)
		known := f != nil || name == "help" || name == "h"
		switch {
		case long && len(name) == 1:
			if known {
				return nil, fmt.Errorf("%s: a one-letter option takes one dash, as -%s", arg, name)
			}
		case !long && len(name) > 1:
			if known {
				return nil, fmt.Errorf("%s: an option's full name takes two dashes, as --%s", arg, name)
			}
			if hasValue || !isBundle(fs, name) {
				return nil, fmt.Errorf("%s is not an option; options are written --name or -n", arg)
			}
			for j := range len(name) - 1 {
				out = append(out, "-"+name[j:j+1])
			}
			arg = "-" + name[len(name)-1:]
			f, known = fs.Lookup(arg[1:]), true
		}
		if !known {
			msg := fmt.Sprintf("unknown option %s", arg)
			if s := suggest(fs, name); s != "" {
				msg += fmt.Sprintf("; did you mean %s?", s)
			}
			return nil, errors.New(msg)
		}
		out = append(out, arg)
		if f != nil && !hasValue && !isBool(f) && i+1 < len(args) {
			i++ // its value, which may itself start with a dash
			out = append(out, args[i])
		}
	}
	return out, nil
}

// isBundle reports whether each letter of name is a one-letter option of fs,
// each but the last a switch.
func isBundle(fs *flag.FlagSet, name string) bool {
	for i := range len(name) {
		f := fs.Lookup(name[i : i+1])
		if f == nil || i < len(name)-1 && !isBool(f) {
			return false
		}
	}
	return true
}

func isBool(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// Spelling is how an option is written: -n for a one-letter name, --name
// otherwise.
func Spelling(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

// Label is how help lists f: "-y, --yes" when a one-letter option shares its
// value, "--yes" otherwise. ok is false for a one-letter alias, which its long
// option's label already shows.
func Label(fs *flag.FlagSet, f *flag.Flag) (label string, ok bool) {
	if len(f.Name) == 1 {
		if long := longFor(fs, f); long != nil {
			return "", false
		}
		return Spelling(f.Name), true
	}
	label = "    --" + f.Name
	fs.VisitAll(func(g *flag.Flag) {
		if len(g.Name) == 1 && g.Value == f.Value {
			label = "-" + g.Name + ", --" + f.Name
		}
	})
	return label, true
}

func longFor(fs *flag.FlagSet, short *flag.Flag) (long *flag.Flag) {
	fs.VisitAll(func(g *flag.Flag) {
		if len(g.Name) > 1 && g.Value == short.Value {
			long = g
		}
	})
	return long
}

// flagName matches the one-dash names the flag package puts in its errors.
var flagName = regexp.MustCompile(`(^|: |for |flag )-([A-Za-z0-9][A-Za-z0-9-]*)`)

// Tidy rewrites an error from fs.Parse with each option spelled as it is
// meant to be written.
func Tidy(err error) error {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return err
	}
	msg := flagName.ReplaceAllStringFunc(err.Error(), func(m string) string {
		sub := flagName.FindStringSubmatch(m)
		return sub[1] + Spelling(sub[2])
	})
	msg = strings.Replace(msg, "flag provided but not defined", "unknown option", 1)
	msg = strings.Replace(msg, "flag needs an argument", "the option needs a value", 1)
	msg = strings.Replace(msg, "for flag ", "for ", 1)
	return errors.New(msg)
}

var invalidValue = regexp.MustCompile(`^invalid value ".*" for flag -([A-Za-z0-9-]+): (parse error|value out of range)$`)

// TidyIn is [Tidy] for an error from parsing fs, and says what an option
// whose value did not parse wants: the flag package's "parse error" does not.
func TidyIn(fs *flag.FlagSet, err error) error {
	if err == nil {
		return nil
	}
	m := invalidValue.FindStringSubmatch(err.Error())
	if m == nil {
		return Tidy(err)
	}
	want := ""
	if f := fs.Lookup(m[1]); f != nil {
		switch fmt.Sprintf("%T", f.Value) {
		case "*flag.durationValue":
			want = "a duration, written like 30m, 2h or 1h30m"
		case "*flag.uintValue", "*flag.uint64Value", "*flag.intValue", "*flag.int64Value":
			want = "a whole number"
			if m[2] == "value out of range" {
				want = "a smaller whole number"
			}
		}
	}
	if want == "" {
		return Tidy(err)
	}
	msg := strings.TrimSuffix(err.Error(), m[2]) + "it takes " + want
	return Tidy(errors.New(msg))
}

// suggest names the option closest to a mistyped one, if one is close.
func suggest(fs *flag.FlagSet, name string) string {
	best, bestDist := "", 3
	if len(name) < 3 {
		bestDist = 2
	}
	fs.VisitAll(func(f *flag.Flag) {
		if d := EditDistance(name, f.Name); d < bestDist && len(f.Name) > 1 {
			best, bestDist = Spelling(f.Name), d
		}
	})
	return best
}

// EditDistance counts the edits between two words, a swap of neighbours
// being one: it is the commonest typo.
func EditDistance(a, b string) int {
	d := make([][]int, len(a)+1)
	for i := range d {
		d[i] = make([]int, len(b)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(a)][len(b)]
}

package cliflag

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
)

func testSet() *flag.FlagSet {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Bool("yes", false, "")
	fs.String("name", "", "")
	fs.Uint("port", 0, "")
	Short(fs, 'y', "yes")
	return fs
}

func TestCheckHoldsOptionsToOneSpelling(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string // "" for accepted
	}{
		{[]string{"--yes", "--name", "x", "--port=3", "pos"}, ""},
		{[]string{"-y", "-h"}, ""},
		{[]string{"--help"}, ""},
		{[]string{"--name", "-looks-like-an-option"}, ""},
		{[]string{"--", "-name", "--whatever"}, ""},
		{[]string{"-", "pos"}, ""},
		{[]string{"-name", "x"}, "takes two dashes, as --name"},
		{[]string{"-help"}, "as --help"},
		{[]string{"--y"}, "takes one dash, as -y"},
		{[]string{"-abc"}, "not an option"},
		{[]string{"--nmae", "x"}, "did you mean --name?"},
		{[]string{"--frobnicate"}, "unknown option --frobnicate"},
		{[]string{"-q"}, "unknown option -q"},
		{[]string{"---yes"}, "not an option"},
	} {
		err := Check(testSet(), tc.args)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%q: %v, want accepted", tc.args, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%q: %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestLabelsShowBothNames(t *testing.T) {
	fs := testSet()
	var labels []string
	fs.VisitAll(func(f *flag.Flag) {
		if l, ok := Label(fs, f); ok {
			labels = append(labels, l)
		}
	})
	want := []string{"    --name", "    --port", "-y, --yes"}
	if strings.Join(labels, "|") != strings.Join(want, "|") {
		t.Fatalf("labels %q, want %q", labels, want)
	}
}

func TestTidyPutsTheDashesBack(t *testing.T) {
	fs := testSet()
	err := Tidy(fs.Parse([]string{"--port", "many"}))
	if err == nil || !strings.Contains(err.Error(), `invalid value "many" for --port`) {
		t.Fatalf("err = %v", err)
	}
	fs = testSet()
	err = Tidy(fs.Parse([]string{"--name"}))
	if err == nil || err.Error() != "the option needs a value: --name" {
		t.Fatalf("err = %v", err)
	}
	if err := Tidy(flag.ErrHelp); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help became %v", err)
	}
}

func TestTidyInSaysWhatAValueShouldBe(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Duration("expires", 0, "")
	err := TidyIn(fs, fs.Parse([]string{"--expires", "5"}))
	if err == nil || err.Error() != `invalid value "5" for --expires: it takes a duration, written like 30m, 2h or 1h30m` {
		t.Fatalf("err = %v", err)
	}
	if err := TidyIn(fs, fs.Parse(nil)); err != nil {
		t.Fatalf("no error became %v", err)
	}
}

func TestIsSetUnderEitherName(t *testing.T) {
	for _, args := range [][]string{{"--yes"}, {"-y"}} {
		fs := testSet()
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		if !IsSet(fs, "yes") || IsSet(fs, "name") {
			t.Errorf("%q: yes set %v, name set %v", args, IsSet(fs, "yes"), IsSet(fs, "name"))
		}
	}
}

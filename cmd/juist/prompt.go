package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// errAborted is a question answered no.
var errAborted = errors.New("aborted")

// A question is a yes/no question for the person at the terminal.
type question struct {
	text string
	// yes is the answer to an empty line.
	yes bool
	// fresh discards what was typed before the question was asked, for one
	// whose answer decides something irreversible, such as whether to sign.
	fresh bool
}

// ask asks q on the terminal. It gives up when ctx ends, and takes the end of
// input as no.
func (a *app) ask(ctx context.Context, q question) (bool, error) {
	if q.fresh {
		if f, ok := a.in.(*os.File); ok {
			flushInput(int(f.Fd()))
		}
	}
	choices := "[y/N]"
	if q.yes {
		choices = "[Y/n]"
	}
	fmt.Fprintf(a.out, "%s %s ", q.text, choices)
	line, err := a.readLine(ctx)
	if ctx.Err() != nil {
		fmt.Fprintln(a.out)
		return false, ctx.Err()
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	case "":
		return q.yes && err == nil, nil
	default:
		return false, nil
	}
}

type readResult struct {
	line string
	err  error
}

// readLine reads a line of a.in. A read that ctx gave up on stays under way,
// and the next call takes its line: one reader, and one read at a time.
func (a *app) readLine(ctx context.Context) (string, error) {
	if a.reader == nil {
		a.reader = bufio.NewReader(a.in)
	}
	if a.reading == nil {
		ch := make(chan readResult, 1)
		go func() {
			line, err := a.reader.ReadString('\n')
			ch <- readResult{line, err}
		}()
		a.reading = ch
	}
	select {
	case r := <-a.reading:
		a.reading = nil
		return r.line, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// askNow asks a question that decides something irreversible: it defaults to
// no, and answers only what is typed after it was asked.
func (a *app) askNow(ctx context.Context, text string) (bool, error) {
	if !a.interactive {
		return false, errors.New("needs an answer from a terminal")
	}
	return a.ask(ctx, question{text: text, fresh: true})
}

// confirm asks a question defaulting to no. Without a terminal to ask on it
// refuses, so a script has to say --yes rather than get a default; an
// interrupt is a no.
func (a *app) confirm(text string) (bool, error) {
	if !a.interactive {
		return false, errors.New("needs confirmation; pass --yes or run in a terminal")
	}
	ok, err := a.ask(a.ctx, question{text: text})
	if errors.Is(err, context.Canceled) {
		return false, errAborted
	}
	return ok, err
}

// proceed is confirm where no is the end of the command; yes skips asking.
func (a *app) proceed(yes bool, text string) error {
	if yes {
		return nil
	}
	ok, err := a.confirm(text)
	if err != nil {
		return err
	}
	if !ok {
		return errAborted
	}
	return nil
}

//go:build !unix

package main

import (
	"context"
	"errors"
	"io"
	"net"
)

func dropTo(string) error { return errors.New("no user to drop to here") }

func runBinder(context.Context, []string, string, io.Writer) error {
	return errors.New("the terminator splits on unix alone")
}

type binder struct{}

func inheritedBinder() (*binder, <-chan struct{}, error) { return nil, nil, nil }

func (*binder) listen(string, string) (net.Listener, error) { return nil, errors.New("no binder") }

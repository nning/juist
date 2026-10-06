//go:build !unix

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"

	"github.com/nning/juist/ipc"
)

func dropTo(string) error { return errors.New("no user to drop to here") }

func runBinder(context.Context, []string, string, func(context.Context, string) (*os.File, error), io.Writer) error {
	return errors.New("a helper splits on unix alone")
}

func bindServed(context.Context, string, func(context.Context) (*ipc.Published, error)) (*os.File, error) {
	return nil, errors.New("no binding here")
}

func bindPublic(context.Context, string, func(context.Context) (*ipc.Published, error)) (*os.File, error) {
	return nil, errors.New("no binding here")
}

type binder struct{}

func inheritedBinder() (*binder, <-chan struct{}, error) { return nil, nil, nil }

func (*binder) listen(string, string) (net.Listener, error) { return nil, errors.New("no binder") }

func (*binder) listenUDP(string) (*net.UDPConn, error) { return nil, errors.New("no binder") }

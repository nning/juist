//go:build !unix

package main

import (
	"errors"
	"io"
)

func spawnBackground([]string) (io.ReadCloser, func() error, func(), error) {
	return nil, nil, nil, errors.New("--background works only on Linux and FreeBSD")
}

func backgroundShare() (io.WriteCloser, func()) { return nil, nil }

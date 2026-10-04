//go:build !unix

package main

import (
	"errors"
	"io"
)

func spawnBackground([]string) (io.ReadCloser, func() error, func(), error) {
	return nil, nil, nil, errors.New("juist shares in the background on Linux and FreeBSD alone")
}

func backgroundShare() (io.WriteCloser, func()) { return nil, nil }

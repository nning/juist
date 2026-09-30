//go:build !linux && !freebsd

package dnsfwd

import (
	"errors"
	"syscall"
)

func bindTo(_ syscall.RawConn, device string) error {
	if device != "" {
		return errors.New("dnsfwd: binding to a device is Linux's alone")
	}
	return nil
}

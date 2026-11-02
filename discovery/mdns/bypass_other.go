//go:build !linux || android

package mdns

import "syscall"

func markUnderlay(syscall.RawConn) error { return nil }

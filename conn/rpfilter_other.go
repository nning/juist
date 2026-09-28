//go:build !linux || android

package conn

// StrictRP6 reports whether firewalld's IPv6 reverse-path filter is strict:
// never, off Linux.
func StrictRP6() (bool, error) { return false, nil }

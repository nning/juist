//go:build !freebsd && !freebsdman

package ipc

// SystemSocket is where the packaged service listens.
const SystemSocket = "/run/juist/juistd.sock"

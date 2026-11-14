//go:build freebsd || freebsdman || darwin

package ipc

// SystemSocket is where the packaged service listens.
const SystemSocket = "/var/run/juist/juistd.sock"

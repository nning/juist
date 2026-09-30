// Package interop is the lab where Linux and FreeBSD nodes meet: a Debian
// and a FreeBSD VM in qemu, each with its package installed, joined in one
// network, each the other's exit node and subnet router. make interop runs
// it; it needs qemu, qemu-img, xz and ssh, and no root.
package interop

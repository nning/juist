package plumber

import "syscall"

// scopedRoute marks a default route of a device other than the primary one,
// which macOS keeps beside it.
const scopedRoute = syscall.RTF_IFSCOPE

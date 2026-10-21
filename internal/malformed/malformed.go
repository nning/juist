// Package malformed turns a panic in a decoder of outside input into an error,
// so that a parser's slip drops what it was decoding rather than the process.
package malformed

import (
	"fmt"
	"runtime"
	"strings"
)

// Recover, deferred directly by a function that decodes bytes and changes
// nothing else, sets *err for a panic in it. A function that touches shared
// state must not use it: a panic there may leave the state half-changed.
func Recover(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("malformed input: %v at %s", r, site())
	}
}

// RecoverOK is [Recover] for a decoder that reports ok rather than an error.
func RecoverOK(ok *bool) {
	if r := recover(); r != nil {
		*ok = false
	}
}

// site is where the panic was raised: the first frame past the runtime's,
// called from the deferred Recover.
func site() string {
	pcs := make([]uintptr, 32)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs)])
	for {
		f, more := frames.Next()
		if !strings.HasPrefix(f.Function, "runtime.") {
			return fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		if !more {
			return "an unknown place"
		}
	}
}

// RecoverWith is [Recover] for a decoder that answers rather than errs: it
// sets *v to what fallback gives.
func RecoverWith[T any](v *T, fallback func() T) {
	if r := recover(); r != nil {
		*v = fallback()
	}
}

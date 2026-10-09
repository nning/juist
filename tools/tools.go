//go:build tools

// Package tools pins the linters make runs where go run pkg@version cannot:
// staticcheck needs a golang.org/x/tools newer than its own release asks for
// to read Go 1.27.2's export data.
package tools

import _ "honnef.co/go/tools/cmd/staticcheck"

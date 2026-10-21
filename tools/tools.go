//go:build tools

// Package tools pins the linters make runs, by this module's go.sum:
// staticcheck needs a golang.org/x/tools newer than its own release asks for
// to read Go 1.27.3's export data.
package tools

import (
	_ "github.com/rhysd/actionlint/cmd/actionlint"
	_ "golang.org/x/vuln/cmd/govulncheck"
	_ "honnef.co/go/tools/cmd/staticcheck"
)

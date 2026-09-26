// Package defaults holds what juist and juistd assume alike when not told.
package defaults

import (
	"os"
	"path/filepath"
)

// Home is the state directory and keystore: $JUIST_HOME, or juist in the
// user's configuration directory.
func Home() string {
	if v := os.Getenv("JUIST_HOME"); v != "" {
		return v
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "juist")
	}
	return ".juist"
}

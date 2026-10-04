// Command licenses writes THIRD_PARTY_LICENSES: the license of Go, of every
// module that juist and juistd link on any v1 target platform, and of what
// they embed from elsewhere, which every binary package must carry.
//
//	go run ./packaging/licenses > THIRD_PARTY_LICENSES
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// platforms are the Makefile's CROSS_PLATFORMS; a test holds them equal.
var platforms = []string{"linux/amd64", "linux/arm64", "freebsd/amd64", "android/arm64"}

var commands = []string{"github.com/nning/juist/cmd/juist", "github.com/nning/juist/cmd/juistd"}

// embedded are the licenses of what the binaries embed from this tree but
// did not write, by the directory that holds each.
var embedded = []struct{ name, dir string }{
	{"IBM Plex fonts, in the pages juist and juistd serve", "internal/webstyle/fonts"},
}

func main() {
	b, err := render()
	if err != nil {
		fmt.Fprintln(os.Stderr, "licenses:", err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
}

func render() ([]byte, error) {
	dirs := map[string]string{}
	for _, p := range platforms {
		goos, goarch, _ := strings.Cut(p, "/")
		cmd := exec.Command("go", append([]string{"list", "-deps", "-f",
			"{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Dir}}{{end}}{{end}}"}, commands...)...)
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list for %s: %v", p, err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if path, dir, ok := strings.Cut(line, "\t"); ok {
				dirs[path] = dir
			}
		}
	}
	root, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return nil, fmt.Errorf("go env GOROOT: %v", err)
	}
	tree, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m: %v", err)
	}
	paths := make([]string, 0, len(dirs))
	for p := range dirs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var b bytes.Buffer
	b.WriteString("juist and juistd contain the following software, under these licenses.\n" +
		"Each module's source is available from https://proxy.golang.org by its path.\n")
	if err := section(&b, "Go", strings.TrimSpace(string(root))); err != nil {
		return nil, err
	}
	for _, p := range paths {
		if err := section(&b, p, dirs[p]); err != nil {
			return nil, err
		}
	}
	for _, e := range embedded {
		if err := section(&b, e.name, filepath.Join(strings.TrimSpace(string(tree)), e.dir)); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

// section appends the license files at the root of dir, failing where there
// are none, so that a new module is not shipped without its notice.
func section(b *bytes.Buffer, name, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	n := 0
	for _, e := range entries {
		u := strings.ToUpper(e.Name())
		if e.IsDir() || strings.HasSuffix(u, ".GO") || !(strings.HasPrefix(u, "LICENSE") || strings.HasPrefix(u, "LICENCE") ||
			strings.HasPrefix(u, "COPYING") || strings.HasPrefix(u, "NOTICE") || u == "PATENTS" || u == "OFL.TXT") {
			continue
		}
		text, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "\n%s\n%s, %s\n\n", strings.Repeat("=", 78), name, e.Name())
		b.Write(bytes.TrimRight(text, "\n"))
		b.WriteString("\n")
		n++
	}
	if n == 0 {
		return fmt.Errorf("%s: no license file in %s", name, dir)
	}
	return nil
}

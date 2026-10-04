// Command mkpkg writes a FreeBSD package, as pkg-create(8) would, from files
// already built, so that any system builds it, and to the same bytes.
//
//	mkpkg -manifest M -scripts DIR -version V -abi FreeBSD:14:amd64 -mtime T -o OUT DEST=SRC...
//
// A DEST ending in .gz whose SRC does not is compressed on the way.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// scriptNames are the scripts pkg runs, by the names it has for them.
var scriptNames = []string{"pre-install", "post-install", "install", "pre-deinstall", "post-deinstall", "deinstall"}

// modeOf is a file's mode by where it goes, not by what the checkout says:
// commands, rc.d scripts and what libexec holds run, the rest is read.
func modeOf(dest string) int64 {
	for _, dir := range []string{"/bin/", "/sbin/", "/etc/rc.d/", "/libexec/"} {
		if strings.Contains(dest, dir) {
			return 0o755
		}
	}
	return 0o644
}

// arches is pkg's name for each ABI's machine.
var arches = map[string]string{"amd64": "x86:64", "aarch64": "aarch64:64"}

type file struct {
	dest string
	mode int64
	data []byte
}

func main() {
	manifest := flag.String("manifest", "", "the package's metadata, JSON")
	scripts := flag.String("scripts", "", "a directory of scripts named as pkg runs them")
	version := flag.String("version", "", "the package's version")
	abi := flag.String("abi", "", "the ABI it installs on, as FreeBSD:14:amd64")
	mtime := flag.Int64("mtime", 0, "every file's time, in seconds since the epoch")
	out := flag.String("o", "", "the package to write")
	flag.Parse()
	if err := run(*manifest, *scripts, *version, *abi, *mtime, *out, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "mkpkg:", err)
		os.Exit(1)
	}
}

func run(manifestPath, scriptDir, version, abi string, mtime int64, out string, specs []string) error {
	parts := strings.Split(abi, ":")
	if len(parts) != 3 || parts[0] != "FreeBSD" || arches[parts[2]] == "" {
		return fmt.Errorf("abi %q: want FreeBSD:MAJOR:amd64 or FreeBSD:MAJOR:aarch64", abi)
	}
	major, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("abi %q: %w", abi, err)
	}
	if version == "" || out == "" || len(specs) == 0 {
		return fmt.Errorf("-version, -o and files are needed")
	}
	var m map[string]any
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("%s: %w", manifestPath, err)
	}
	var files []file
	for _, s := range specs {
		dest, src, ok := strings.Cut(s, "=")
		if !ok || !path.IsAbs(dest) || path.Clean(dest) != dest {
			return fmt.Errorf("%q: want /DEST=SRC, DEST clean", s)
		}
		if slices.ContainsFunc(files, func(f file) bool { return f.dest == dest }) {
			return fmt.Errorf("%s twice", dest)
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		files = append(files, file{dest: dest, mode: modeOf(dest)})
		f := &files[len(files)-1]
		if strings.HasSuffix(dest, ".gz") && !strings.HasSuffix(src, ".gz") {
			var z bytes.Buffer
			w, _ := gzip.NewWriterLevel(&z, gzip.BestCompression)
			w.Write(data)
			if err := w.Close(); err != nil {
				return err
			}
			data = z.Bytes()
		}
		f.data = data
	}
	slices.SortFunc(files, func(a, b file) int { return strings.Compare(a.dest, b.dest) })

	m["version"] = version
	m["abi"] = abi
	m["arch"] = fmt.Sprintf("freebsd:%d:%s", major, arches[parts[2]])
	// The oldest release of the major, so that every one of them takes it.
	m["annotations"] = map[string]string{"FreeBSD_version": strconv.Itoa(major * 100000)}
	var flatsize int
	for _, f := range files {
		flatsize += len(f.data)
	}
	m["flatsize"] = flatsize
	compact, err := json.Marshal(m)
	if err != nil {
		return err
	}
	sums := map[string]any{}
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		sums[f.dest] = map[string]any{"sum": "1$" + hex.EncodeToString(sum[:]), "uname": "root", "gname": "wheel",
			"perm": fmt.Sprintf("%04o", f.mode), "mtime": mtime}
	}
	m["files"] = sums
	if scriptDir != "" {
		entries, err := os.ReadDir(scriptDir)
		if err != nil {
			return err
		}
		sc := map[string]string{}
		for _, e := range entries {
			if !slices.Contains(scriptNames, e.Name()) {
				return fmt.Errorf("%s: %s is no script pkg runs", scriptDir, e.Name())
			}
			b, err := os.ReadFile(filepath.Join(scriptDir, e.Name()))
			if err != nil {
				return err
			}
			sc[e.Name()] = string(b)
		}
		m["scripts"] = sc
	}
	full, err := json.Marshal(m)
	if err != nil {
		return err
	}

	var pkg bytes.Buffer
	z, _ := gzip.NewWriterLevel(&pkg, gzip.BestCompression)
	tw := tar.NewWriter(z)
	put := func(name string, mode int64, t int64, data []byte) error {
		h := &tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Uname: "root", Gname: "wheel",
			ModTime: time.Unix(t, 0), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	// The manifests first, which pkg reads before the files.
	if err := put("+COMPACT_MANIFEST", 0o644, 0, compact); err != nil {
		return err
	}
	if err := put("+MANIFEST", 0o644, 0, full); err != nil {
		return err
	}
	for _, f := range files {
		if err := put(f.dest, f.mode, mtime, f.data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}
	return os.WriteFile(out, pkg.Bytes(), 0o644)
}

// Command mkimage writes the service member's container image, as docker
// save would, from binaries already built, so that any system builds it,
// and to the same bytes; docker load and podman load take it.
//
//	mkimage -o OUT -tag juist:V -arch amd64 -mtime T -juistd F -juist F -certs F \
//		-license F -third-party F
//
// The image holds juistd and juist, their licenses, the CA certificates and a
// user of their own, and runs juistd as that user with its home in a volume.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

// uid is the image's user, the one distroless images run as.
const uid = 65532

// home is where juistd keeps its state, a volume.
const home = "/var/lib/juist"

func main() {
	out := flag.String("o", "", "the image to write")
	tag := flag.String("tag", "", "its name, as juist:1.0")
	arch := flag.String("arch", "", "the machine it runs on, amd64 or arm64")
	mtime := flag.Int64("mtime", 0, "every file's time, in seconds since the epoch")
	juistd := flag.String("juistd", "", "juistd, built for linux")
	juist := flag.String("juist", "", "juist, built for linux")
	certs := flag.String("certs", "", "the CA certificates, PEM")
	license := flag.String("license", "", "juist's license")
	thirdParty := flag.String("third-party", "", "the licenses of what juist links")
	flag.Parse()
	if err := run(*out, *tag, *arch, *mtime, *juistd, *juist, *certs, *license, *thirdParty); err != nil {
		fmt.Fprintln(os.Stderr, "mkimage:", err)
		os.Exit(1)
	}
}

type entry struct {
	name string
	mode int64
	uid  int
	data []byte
	dir  bool
}

func run(out, tag, arch string, mtime int64, juistd, juist, certs, license, thirdParty string) error {
	if out == "" || tag == "" || (arch != "amd64" && arch != "arm64") {
		return fmt.Errorf("-o, -tag and -arch amd64 or arm64 are needed")
	}
	read := func(p string) ([]byte, error) {
		if p == "" {
			return nil, fmt.Errorf("-juistd, -juist, -certs, -license and -third-party are needed")
		}
		return os.ReadFile(p)
	}
	d, err := read(juistd)
	if err != nil {
		return err
	}
	c, err := read(juist)
	if err != nil {
		return err
	}
	ca, err := read(certs)
	if err != nil {
		return err
	}
	lic, err := read(license)
	if err != nil {
		return err
	}
	third, err := read(thirdParty)
	if err != nil {
		return err
	}
	entries := []entry{
		{name: "etc/", mode: 0o755, dir: true},
		{name: "etc/group", mode: 0o644, data: fmt.Appendf(nil, "root:x:0:\njuist:x:%d:\n", uid)},
		{name: "etc/passwd", mode: 0o644,
			data: fmt.Appendf(nil, "root:x:0:0:root:/root:/sbin/nologin\njuist:x:%d:%d:juist:%s:/sbin/nologin\n", uid, uid, home)},
		{name: "etc/ssl/", mode: 0o755, dir: true},
		{name: "etc/ssl/certs/", mode: 0o755, dir: true},
		{name: "etc/ssl/certs/ca-certificates.crt", mode: 0o644, data: ca},
		{name: "tmp/", mode: 0o1777, dir: true},
		{name: "usr/", mode: 0o755, dir: true},
		{name: "usr/local/", mode: 0o755, dir: true},
		{name: "usr/local/bin/", mode: 0o755, dir: true},
		{name: "usr/local/bin/juist", mode: 0o755, data: c},
		{name: "usr/local/bin/juistd", mode: 0o755, data: d},
		{name: "usr/local/share/", mode: 0o755, dir: true},
		{name: "usr/local/share/doc/", mode: 0o755, dir: true},
		{name: "usr/local/share/doc/juist/", mode: 0o755, dir: true},
		{name: "usr/local/share/doc/juist/LICENSE", mode: 0o644, data: lic},
		{name: "usr/local/share/doc/juist/THIRD_PARTY_LICENSES", mode: 0o644, data: third},
		{name: "var/", mode: 0o755, dir: true},
		{name: "var/lib/", mode: 0o755, dir: true},
		{name: "var/lib/juist/", mode: 0o700, uid: uid, dir: true},
	}
	t := time.Unix(mtime, 0).UTC()
	var layer bytes.Buffer
	if err := writeTar(&layer, t, entries); err != nil {
		return err
	}
	diff := sha256.Sum256(layer.Bytes())
	config, err := json.Marshal(imageConfig{
		Architecture: arch, OS: "linux", Created: t.Format(time.RFC3339),
		Config: containerConfig{
			User:       fmt.Sprintf("%d:%d", uid, uid),
			Env:        []string{"PATH=/usr/local/bin", "HOME=" + home},
			Entrypoint: []string{"/usr/local/bin/juistd", "--home", home},
			WorkingDir: home,
			Volumes:    map[string]struct{}{home: {}},
		},
		RootFS: rootFS{Type: "layers", DiffIDs: []string{"sha256:" + hex.EncodeToString(diff[:])}},
	})
	if err != nil {
		return err
	}
	configSum := sha256.Sum256(config)
	configName := hex.EncodeToString(configSum[:]) + ".json"
	layerName := hex.EncodeToString(diff[:]) + "/layer.tar"
	manifest, err := json.Marshal([]archiveManifest{{Config: configName, RepoTags: []string{tag}, Layers: []string{layerName}}})
	if err != nil {
		return err
	}
	var archive bytes.Buffer
	if err := writeTar(&archive, t, []entry{
		{name: hex.EncodeToString(diff[:]) + "/", mode: 0o755, dir: true},
		{name: layerName, mode: 0o644, data: layer.Bytes()},
		{name: configName, mode: 0o644, data: config},
		{name: "manifest.json", mode: 0o644, data: manifest},
	}); err != nil {
		return err
	}
	return os.WriteFile(out, archive.Bytes(), 0o644)
}

func writeTar(w *bytes.Buffer, t time.Time, entries []entry) error {
	tw := tar.NewWriter(w)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: e.mode, Uid: e.uid, Gid: e.uid, ModTime: t, Format: tar.FormatPAX,
			Typeflag: tar.TypeReg, Size: int64(len(e.data))}
		if e.dir {
			h.Typeflag, h.Size = tar.TypeDir, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if _, err := tw.Write(e.data); err != nil {
			return err
		}
	}
	return tw.Close()
}

type imageConfig struct {
	Architecture string          `json:"architecture"`
	OS           string          `json:"os"`
	Created      string          `json:"created"`
	Config       containerConfig `json:"config"`
	RootFS       rootFS          `json:"rootfs"`
}

type containerConfig struct {
	User       string              `json:"User"`
	Env        []string            `json:"Env"`
	Entrypoint []string            `json:"Entrypoint"`
	WorkingDir string              `json:"WorkingDir"`
	Volumes    map[string]struct{} `json:"Volumes"`
}

type rootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type archiveManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

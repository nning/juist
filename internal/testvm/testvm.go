// Package testvm is what the CI runner and the interop lab share to boot a
// cloud image under qemu: fetching it, checking its sum, and serving its
// cloud-init NoCloud seed.
package testvm

import (
	"context"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Fetch writes url's body to path by way of path+".part", so that an
// interrupted fetch leaves no file at path.
func Fetch(ctx context.Context, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: time.Hour}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	f, err := os.Create(path + ".part")
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(path+".part", path)
}

// Sum is path's contents hashed by h, in hex.
func Sum(path string, h func() hash.Hash) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := h()
	if _, err := io.Copy(s, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(s.Sum(nil)), nil
}

// Check fails unless path's contents hash by h to want.
func Check(path string, h func() hash.Hash, want string) error {
	got, err := Sum(path, h)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s: sum %s, want %s", path, got, want)
	}
	return nil
}

// ServeSeed serves on the host's loopback the NoCloud seed of a VM named
// hostname, with userData its cloud-config, until stop is called.
func ServeSeed(hostname, userData string) (port int, stop func(), err error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/meta-data", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "instance-id: %s\nlocal-hostname: %s\n", hostname, hostname)
	})
	mux.HandleFunc("/user-data", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, userData) })
	mux.HandleFunc("/vendor-data", func(http.ResponseWriter, *http.Request) {})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	return l.Addr().(*net.TCPAddr).Port, func() { srv.Close() }, nil
}

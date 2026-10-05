package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nning/juist/internal/webstyle"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// maxShare bounds --for, as an invite's --expires is.
const maxShare = 7 * 24 * time.Hour

func cmdShare(a *app, args []string) error {
	s := spec{name: "juist share", args: "FILE|DIR | --stop", min: 1, max: 1, about: `
Share FILE or DIR read-only from the internet, under this device's own name
and a random path, until Ctrl-C or for --for; nothing else is reached
there. A directory is listed, and downloads whole as a ZIP. With
--background, it shares on until juist share --stop or --for. The device
needs the publish role.`}
	fs := newFlags(s.name)
	var dur longDuration
	fs.Var(&dur, "for", "share for `DURATION`, like 2h or 7d")
	bg := fs.Bool("background", false, "share in the background")
	stop := fs.Bool("stop", false, "stop this device's share, juist publish PORT's too")
	if slices.ContainsFunc(args, func(w string) bool { return w == "--stop" || w == "-stop" || w == "-S" }) {
		s.min = 0
	}
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	if *stop {
		if len(pos) > 0 || *bg || dur != 0 {
			return fmt.Errorf("--stop takes nothing else\n%s", s.usage(fs))
		}
		return a.stopShare()
	}
	if time.Duration(dur) < 0 || time.Duration(dur) > maxShare {
		return errors.New("--for must be between 1s and 7d")
	}
	path, info, err := sharedPath(pos[0])
	if err != nil {
		return err
	}
	token, err := shareToken()
	if err != nil {
		return err
	}
	handler, under, err := shareHandler(path, info, token)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute}
	go srv.Serve(ln)
	defer srv.Close()
	req := ipc.ShareRequest{To: ln.Addr().String(), What: path, Path: under}
	return a.shareLocal(req, time.Duration(dur), *bg, func(name string) string {
		return fmt.Sprintf("sharing %s at https://%s%s", pos[0], name, under)
	})
}

// publishPort publishes the HTTP server on this host's PORT under this
// device's own name, as juist share does a file.
func publishPort(a *app, args []string) error {
	s := spec{name: "juist publish", args: "PORT", min: 1, max: 1, about: `
Publish the HTTP server on this host's PORT under this device's own name,
until Ctrl-C or for --for; with --background, until juist share --stop or
--for. The device needs the publish role.`}
	fs := newFlags(s.name)
	var dur longDuration
	fs.Var(&dur, "for", "publish for `DURATION`, like 2h or 7d")
	bg := fs.Bool("background", false, "publish in the background")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	if time.Duration(dur) < 0 || time.Duration(dur) > maxShare {
		return errors.New("--for must be between 1s and 7d")
	}
	port, err := strconv.ParseUint(pos[0], 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("%q is no port", pos[0])
	}
	// IPv4's loopback, or IPv6's where only it answers, as a server bound to
	// localhost may be.
	to := ""
	for _, host := range []string{"127.0.0.1", "::1"} {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(host, pos[0]), time.Second); err == nil {
			c.Close()
			to = net.JoinHostPort(host, pos[0])
			break
		}
	}
	if to == "" {
		to = net.JoinHostPort("127.0.0.1", pos[0])
		a.warn("nothing answers on %s yet", to)
	}
	return a.shareLocal(ipc.ShareRequest{To: to}, time.Duration(dur), *bg, func(name string) string {
		return fmt.Sprintf("publishing %s at https://%s", to, name)
	})
}

// publishesPort reports whether args are juist publish's PORT form: a
// number first, past --for and its value and a network's name, that names
// no network.
func publishesPort(a *app, args []string) bool {
	var words []string
	for i := 0; i < len(args); i++ {
		switch w := args[i]; {
		case w == "--for" || w == "-for" || w == "-t" || w == "--t":
			i++
		case strings.HasPrefix(w, "-"):
		default:
			words = append(words, w)
		}
	}
	if len(words) > 1 && a.namesNetwork(words[0]) {
		words = words[1:]
	}
	return len(words) > 0 && strings.Trim(words[0], "0123456789") == "" && !a.namesNetwork(words[0])
}

// shareLocal publishes this device under its own name, as req says, for dur,
// zero for until Ctrl-C, or in the background; saying says what is shared
// where.
func (a *app) shareLocal(req ipc.ShareRequest, dur time.Duration, background bool, saying func(name string) string) error {
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	if st.Instance != 0 {
		return errors.New("juist shares from the default network's instance alone, for now")
	}
	if a.host.serveScript == "" {
		return errors.New("juist ends TLS on Linux and FreeBSD alone")
	}
	if background && a.ready == nil {
		return a.shareInBackground(st)
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	var until time.Time
	if dur > 0 {
		until = time.Now().Add(dur)
		req.Until = until.Unix()
	}
	self := cmp.Or(st.SelfName, st.Self.ShortString())
	said := false
	var lost time.Time
	for {
		err = n.converse(a.ctx, ipc.Request{Command: ipc.CmdShare, Share: &req},
			func(_ context.Context, e *ipc.Event, _ func(ipc.Request) error) error {
				if e.Kind != ipc.EventSharing {
					return nil
				}
				// Started by the package's script, as root, only where it runs not.
				if now, _ := n.restatus(); terminatorDown(now) {
					if err := a.startTerminator(); err != nil {
						return err
					}
				}
				a.sayShare(st, saying(e.Name), until, !said)
				if !said && a.ready != nil {
					a.detachShare()
				}
				said, lost = true, time.Time{}
				return nil
			})
		// In the background, a share outlives a restart of juistd, under the
		// same path, unless juistd refused it.
		if a.ready == nil || !said || err == nil || a.ctx.Err() != nil || juistdRefused(err) ||
			!until.IsZero() && !time.Now().Before(until) {
			break
		}
		if lost.IsZero() {
			lost = time.Now()
		} else if time.Since(lost) > shareRetryFor {
			break
		}
		select {
		case <-a.ctx.Done():
		case <-time.After(shareRetry):
		}
	}
	switch {
	case err != nil && err.Error() == errNoPublishRole:
		return fmt.Errorf("%v\nhint: an admin grants it: juist grant %s publish", err, self)
	case err != nil && err.Error() == errNoDomain:
		return fmt.Errorf("%v\nhint: juist network domain pub.example.org", err)
	case err != nil && a.ctx.Err() != nil && !said:
		return nil // stopped before it started
	case err != nil && a.ctx.Err() == nil && said:
		return errors.New("the share ended with juistd")
	case err != nil && a.ctx.Err() == nil:
		return err
	case said:
		a.ok("stopped sharing")
	}
	return nil
}

// A background share whose juistd went asks again every shareRetry, for
// shareRetryFor at most.
var (
	shareRetry    = 2 * time.Second
	shareRetryFor = 10 * time.Minute
)

// juistdRefused reports whether err is juistd's refusal of a share, which
// asking again does not change.
func juistdRefused(err error) bool {
	switch err.Error() {
	case errNoPublishRole, errNoDomain, errSharing:
		return true
	}
	return false
}

// stopShare ends this device's share, whichever command holds it.
func (a *app) stopShare() error {
	if _, err := a.daemonStatus(); err != nil {
		return err
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	if _, err := ipc.Call(n.socket(), ipc.Request{Command: ipc.CmdUnshare}); err != nil {
		if err.Error() == errNotSharing {
			a.ok("unchanged: not sharing")
			return nil
		}
		return err
	}
	a.ok("stopped sharing")
	return nil
}

// terminatorDown reports whether no terminator runs, as st says.
func terminatorDown(st *ipc.Status) bool {
	return st == nil || st.Terminator == nil || !st.Terminator.Running
}

// sayShare says what is shared where, again after a rename or restart, and
// the first time what keeps the internet from it.
func (a *app) sayShare(st *ipc.Status, what string, until time.Time, first bool) {
	end := "until Ctrl-C"
	switch {
	case a.ready != nil && until.IsZero():
		end = "until juist share --stop"
	case a.ready != nil:
		end = "until " + until.Format("Jan 2 15:04") + ", or juist share --stop"
	case !until.IsZero():
		end = "until " + until.Format("Jan 2 15:04")
	}
	a.ok("%s, %s", what, end)
	if first {
		a.warnFirewalled(st, sharePort)
	}
	if first && !slices.ContainsFunc(st.Devices, func(d ipc.Device) bool { return slices.Contains(d.Roles, types.RoleIngress) }) {
		a.warn("the network has no ingress, so nothing reaches it from the internet")
	}
}

// sharePort is where juistd has a share reached on this device.
const sharePort = 443

// juistd's words for why a share is refused or reaches nobody.
const (
	errNoPublishRole     = "this device holds no publish role"
	errNoDomain          = "the network has no domain to publish under"
	errSharing           = "this device shares already"
	errNotSharing        = "this device shares nothing"
	terminatorNotRunning = "the terminator does not run"
)

// sharedPath is what arg names, as shared: what a link points at, from
// where it is.
func sharedPath(arg string) (string, os.FileInfo, error) {
	path, err := filepath.EvalSymlinks(arg)
	if err != nil {
		return "", nil, fmt.Errorf("nothing to share at %s", arg)
	}
	if path, err = filepath.Abs(path); err != nil {
		return "", nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", nil, fmt.Errorf("nothing to share at %s", arg)
	}
	return path, info, nil
}

// shareToken is a random 128-bit path segment.
func shareToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// shareHandler serves shared, a file or a directory, read-only under token
// and nothing else, dot-entries hidden, and says the path it is reached
// under, escaped. A directory is listed, or sent as a ZIP with ?zip.
func shareHandler(shared string, info os.FileInfo, token string) (http.Handler, string, error) {
	dir, file := shared, ""
	if !info.IsDir() {
		dir, file = filepath.Dir(shared), filepath.Base(shared)
	}
	// Nothing outside it, by a link or otherwise.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	visible := dotless{root.FS()}
	top := filepath.Base(dir)
	prefix := "/" + token + "/"
	files := http.StripPrefix(prefix[:len(prefix)-1], http.FileServerFS(visible))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// The token is the secret: no link out takes it along, and nothing
		// shared runs as the name's origin.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Robots-Tag", "noindex")
		h.Set("Content-Security-Policy", "sandbox")
		h.Set("X-Content-Type-Options", "nosniff")
		clean := path.Clean(r.URL.Path)
		rel, under := strings.CutPrefix(clean+"/", prefix)
		rel = strings.TrimSuffix(rel, "/")
		switch {
		case r.Method != http.MethodGet && r.Method != http.MethodHead:
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
		case !under || !strings.HasPrefix(r.URL.Path, prefix) || clean != r.URL.Path && clean+"/" != r.URL.Path:
			http.NotFound(w, r)
		case file == "" && strings.HasPrefix(rel, shareAssets):
			webstyle.ServeAsset(w, r, strings.TrimPrefix(rel, shareAssets))
		case file != "":
			if rel != file {
				http.NotFound(w, r)
				return
			}
			serveFile(w, r, root, file)
		default:
			name := cmp.Or(rel, ".")
			info, err := fs.Stat(visible, name)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			if info.IsDir() && strings.HasSuffix(r.URL.Path, "/") {
				if r.URL.Query().Has("zip") {
					serveZip(w, r, visible, name, path.Base(path.Join(top, rel)))
					return
				}
				if _, err := fs.Stat(visible, path.Join(name, "index.html")); err != nil {
					serveListing(w, r, visible, name, top, prefix)
					return
				}
			}
			files.ServeHTTP(w, r)
		}
	}), prefix + url.PathEscape(file), nil
}

// serveFile serves name from root as it is, whatever it is called.
func serveFile(w http.ResponseWriter, r *http.Request, root *os.Root, name string) {
	f, err := root.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, name, info.ModTime(), f)
}

// dotless is a file system without its dot-entries, which a shared directory
// holds for itself, as .git or .env.
type dotless struct{ fs.FS }

func (d dotless) Open(name string) (fs.File, error) {
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") && part != "." {
			return nil, fs.ErrNotExist
		}
	}
	f, err := d.FS.Open(name)
	if err != nil {
		return nil, err
	}
	if dir, ok := f.(fs.ReadDirFile); ok {
		return dotlessDir{dir}, nil
	}
	return f, nil
}

type dotlessDir struct{ fs.ReadDirFile }

func (d dotlessDir) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := d.ReadDirFile.ReadDir(n)
	return slices.DeleteFunc(entries, func(e fs.DirEntry) bool { return strings.HasPrefix(e.Name(), ".") }), err
}

// shareSummary is the status line of what this device publishes under its
// own name; paint colours one that reaches nobody.
func shareSummary(sh *ipc.Share, paint func(code, s string) string) string {
	if sh == nil {
		return ""
	}
	end := "until stopped"
	if sh.Until != 0 {
		end = "until " + time.Unix(sh.Until, 0).Format("Jan 2 15:04")
	}
	line := fmt.Sprintf("%s to %s, %s", cmp.Or(sh.Name, "this device's name"), sh.To, end)
	switch {
	case sh.What != "" && sh.Name != "":
		line = fmt.Sprintf("%s at https://%s%s, %s", sh.What, sh.Name, sh.Path, end)
	case sh.What != "":
		line = fmt.Sprintf("%s, %s", sh.What, end)
	}
	if sh.NotShared != "" {
		return paint("33", line+", reached by nobody: "+sh.NotShared)
	}
	return line
}

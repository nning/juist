package packaging

import (
	"cmp"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// newSysextHost stubs mksquashfs by tar, and systemd-sysext refresh by
// taking the last merge's files out of /usr and unpacking the image there.
func newSysextHost(t *testing.T) *manualHost {
	h := newManualHost(t)
	h.script = "sysext.sh"
	h.write(filepath.Join(h.bin, "mksquashfs"), "#!/bin/sh\necho \"mksquashfs $*\" >> "+h.calls+
		"\ntar -cf \"$2\" -C \"$1\" usr\n", 0o755)
	h.write(filepath.Join(h.bin, "systemd-sysext"), `#!/bin/sh
echo "systemd-sysext $*" >> `+h.calls+`
merged=$DESTDIR/../merged
[ ! -f "$merged" ] || (cd "$DESTDIR" && sort -r "$merged" | while read -r f; do rm -f "$f" 2>/dev/null || rmdir "$f" 2>/dev/null; done)
rm -f "$merged"
img=$DESTDIR/var/lib/extensions/juist.raw
[ ! -f "$img" ] || { tar -xpf "$img" -C "$DESTDIR" && tar -tf "$img" > "$merged"; }
`, 0o755)
	return h
}

func TestASysextInstallUpgradesAndRemovesCleanly(t *testing.T) {
	linuxPackagesOnly(t)
	h := newSysextHost(t)
	img := h.root + "/var/lib/extensions/juist.raw"
	if err := os.MkdirAll(filepath.Join(h.root, "etc/atomic-update.conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}

	stage := h.stage("usr/share/doc/juist/old")
	if err := os.Chmod(filepath.Join(stage, "usr/share/doc/juist/old"), 0o666); err != nil {
		t.Fatal(err)
	}
	out := h.must("install", stage)
	wants(t, "a first install", out, []string{
		"-comp zstd -all-root",
		"systemctl enable --quiet systemd-sysext.service", "systemd-sysext refresh", "systemctl daemon-reload",
		"systemd-sysusers " + h.root + "/usr/lib/sysusers.d/juist.conf",
		"chown juist:juist " + h.root + "/var/lib/juist",
		"systemctl try-restart polkit.service", "systemctl enable --quiet juist-sysext.service",
		"firewall.sh reload", "firewall.sh allow",
		"systemctl enable --now --quiet juistd.service", "systemctl enable --now --quiet juist-serve.path",
		"hint: sudo /usr/lib/juist/sysext.sh uninstall",
	}, []string{"try-restart juistd"})
	if b, err := os.ReadFile(filepath.Join(h.root, "usr/lib/extension-release.d/extension-release.juist")); string(b) != "ID=_any\n" {
		t.Errorf("the extension's release file holds %q, %v", b, err)
	}
	keep := "/etc/firewalld/zones/trusted.xml\n/etc/sysctl.d/60-juist-exit.conf\n/etc/avahi/avahi-daemon.conf\n"
	if b, err := os.ReadFile(filepath.Join(h.root, "etc/systemd/system/juist-sysext.service")); !strings.Contains(string(b),
		"\nAfter=systemd-sysext.service\n") || !strings.Contains(string(b), "\nExecStart=/usr/lib/juist/sysext.sh boot\n") {
		t.Errorf("the unit that starts juist at boot holds %q, %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(h.root, "etc/atomic-update.conf.d/juist.conf")); string(b) != keep {
		t.Errorf("SteamOS is told to keep %q, %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(h.root, "usr/bin/juistd")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("juistd installed as %v, %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(h.root, "usr/share/doc/juist/old")); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("a file others could write became %v, %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(h.root, "var/lib/juist")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("/var/lib/juist made as %v, %v", fi, err)
	}
	if !strings.Contains(out, "mksquashfs ") || !strings.Contains(out, " "+img+".new ") {
		t.Errorf("the image was not made beside the one it replaces:\n%s", out)
	}

	out = h.must("install", h.stage())
	wants(t, "an upgrade", out, []string{
		"systemd-sysext refresh", "instances.sh move",
		"systemctl try-restart juistd.service juist-ingress.service juist-serve.service juistd@juist1.service",
		"firewall.sh reload",
	}, []string{"firewall.sh allow", "enable --now", "hint:"})
	if h.exists("usr/share/doc/juist/old") {
		t.Error("an upgrade left a file the new package does not hold")
	}
	if h.exists("var/lib/extensions/juist.raw.new") {
		t.Error("an upgrade left the new image beside the extension")
	}

	h.write(filepath.Join(h.root, "var/lib/juist/node.keys"), "", 0o600)
	h.write(filepath.Join(h.root, "var/lib/juist-serve/account"), "", 0o600)
	if err := os.MkdirAll(filepath.Join(h.root, "var/lib/juist3"), 0o700); err != nil {
		t.Fatal(err)
	}
	out = h.must("uninstall")
	wants(t, "a removal", out, []string{
		"systemctl disable --now --quiet juistd.service juist-serve.path juist-ingress-ports.path juist-sysext.service",
		"firewall.sh revoke", "ingress.sh off", "serve.sh off", "relay.sh off", "exit-node.sh off",
		"exit-node.sh clear", "systemd-sysext refresh", "systemctl daemon-reload",
		"kept /var/lib/juist, which still holds this device's keys", "kept /var/lib/juist-serve",
	}, []string{"kept /var/lib/juist3"})

	var left []string
	filepath.WalkDir(h.root, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			left = append(left, cmp.Or(strings.TrimPrefix(p, h.root), "/"))
		}
		return nil
	})
	want := []string{"/", "/etc", "/etc/atomic-update.conf.d", "/etc/systemd", "/etc/systemd/system",
		"/usr", "/usr/share", "/usr/share/hosts-own",
		"/var", "/var/lib",
		"/var/lib/juist", "/var/lib/juist/node.keys", "/var/lib/juist-serve", "/var/lib/juist-serve/account"}
	if !slices.Equal(left, want) {
		t.Errorf("a removal left\n%v\nwant\n%v", left, want)
	}

	out = h.must("install", h.stage())
	wants(t, "a reinstall", out, []string{"firewall.sh allow", "enable --now --quiet juistd.service"}, nil)
}

func TestASysextInstallTakesAnUnpackedJuistAlone(t *testing.T) {
	linuxPackagesOnly(t)
	h := newSysextHost(t)
	out, err := h.run("install", t.TempDir())
	if err == nil || !strings.Contains(out, "holds no unpacked juist") {
		t.Fatalf("installed a tree without juist: %v\n%s", err, out)
	}
	if h.exists("var/lib/extensions") {
		t.Error("a refused install made the extension")
	}
	if out, err := h.run("uninstall"); err == nil || !strings.Contains(out, "juist: juist is not installed as a system extension") {
		t.Errorf("removed an extension it did not install: %v\n%s", err, out)
	}
}

// At boot, the units of juist's that are enabled are started, and no others.
func TestASysextBootStartsWhatIsEnabled(t *testing.T) {
	linuxPackagesOnly(t)
	h := newSysextHost(t)
	h.write(filepath.Join(h.bin, "systemctl"), `#!/bin/sh
echo "systemctl $*" >> `+h.calls+`
case "$*" in
"is-enabled --quiet juistd.service" | "is-enabled --quiet juistd@juist2.service") exit 0 ;;
is-enabled*) exit 1 ;;
esac
`, 0o755)
	out := h.must("boot")
	var started []string
	for _, l := range strings.Split(out, "\n") {
		if u, ok := strings.CutPrefix(l, "systemctl start --no-block "); ok {
			started = append(started, u)
		}
	}
	if want := []string{"juistd.service", "juistd@juist2.service"}; !slices.Equal(started, want) {
		t.Errorf("boot started %v, want %v:\n%s", started, want, out)
	}
	wants(t, "boot", out, []string{"is-enabled --quiet juist-serve.path", "is-enabled --quiet juistd@juist9.service"}, nil)
}

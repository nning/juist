package packaging

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
)

// ingress.sh starts the ingress and lets 443 and 80 through an active
// firewall, and takes both back, from a stopped firewalld too.
func TestIngressScriptOpensAndCloses(t *testing.T) {
	sb := newSandbox(t)
	for _, name := range []string{"firewall-cmd", "ufw"} {
		body := "#!/bin/sh\necho \"" + name + " $*\" >> " + filepath.Join(sb.root, "calls") + "\n"
		if name == "ufw" {
			body += "[ \"$1\" = status ] && echo 'Status: active'\n"
		}
		if err := os.WriteFile(filepath.Join(sb.root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile("ingress.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(sb.root, "ingress.sh")
	b = []byte(strings.NewReplacer("/run/juist-ingress-ports.lock", sb.root+"/lock",
		"/var/lib/juist-ingress-ports/", sb.root+"/var/lib/juist-ingress-ports/").Replace(string(b)))
	if err := os.WriteFile(script, b, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command("/bin/sh", append([]string{script}, args...)...)
		cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		return string(out) + sb.calls(), err
	}
	calls, err := run("on")
	for _, want := range []string{"systemctl enable --now --quiet juist-ingress.service",
		"systemctl enable --now --quiet juist-ingress-ports.path", "firewall-cmd --add-service=juist-ingress",
		"firewall-cmd --permanent --add-service=juist-ingress", "ufw allow juist-ingress"} {
		if err != nil || !strings.Contains(calls, want) {
			t.Fatalf("on lacks %q (%v):\n%s", want, err, calls)
		}
	}
	calls, err = run("off")
	for _, want := range []string{"systemctl disable --now juist-ingress.service juist-ingress-ports.path",
		"firewall-cmd --remove-service=juist-ingress",
		"firewall-cmd --permanent --remove-service=juist-ingress", "ufw delete allow juist-ingress"} {
		if err != nil || !strings.Contains(calls, want) {
			t.Fatalf("off lacks %q (%v):\n%s", want, err, calls)
		}
	}
	if calls, err := run("open"); err == nil {
		t.Fatalf("an unknown action succeeded:\n%s", calls)
	}

	// A firewall that refuses is said, and the ingress runs all the same.
	refusing := "#!/bin/sh\n[ \"$1\" = --state ] && exit 0\nexit 1\n"
	if err := os.WriteFile(filepath.Join(sb.root, "bin", "firewall-cmd"), []byte(refusing), 0o755); err != nil {
		t.Fatal(err)
	}
	if calls, err := run("on"); err != nil || !strings.Contains(calls, "warning: firewalld did not let juist-ingress in") {
		t.Fatalf("a refusing firewalld (%v):\n%s", err, calls)
	}
}

// ingress.sh has an active firewalld and ufw let exactly the public ports
// juistd lists through while the ingress is enabled, takes back what it let
// through once no longer listed, and leaves the ports others opened alone;
// what juistd's file says is no port, or a port of juist's or the ingress's
// TLS, is let through nowhere, and ufw's rule of someone else's for a port
// stays theirs.
func TestIngressScriptFollowsThePorts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress.sh is Linux's, with its flock, timeout and dd")
	}
	sb := newSandbox(t)
	fw, ufwRules := filepath.Join(sb.root, "fw-open"), filepath.Join(sb.root, "ufw-rules")
	stubs := map[string]string{
		"firewall-cmd": `case $1 in
--state) exit 0 ;;
--permanent) f=` + fw + `.permanent; shift ;;
*) f=` + fw + ` ;;
esac
case $1 in
--query-port=*) p=${1#--query-port=}; grep -qx "$p" $f 2>/dev/null ;;
--add-port=*) echo "${1#--add-port=}" >> $f ;;
--remove-port=*) grep -vx "${1#--remove-port=}" $f > $f.new; mv $f.new $f ;;
esac`,
		"ufw": `case "$*" in
status) echo 'Status: active' ;;
"show added") echo "Added user rules (see 'ufw status' for running firewall):"; echo "ufw allow 8081/tcp"; while read -r p; do echo "ufw allow $p/tcp comment 'juist-ingress'"; done < ` + ufwRules + ` ;;
"allow "*" comment juist-ingress") echo "${2%/tcp}" >> ` + ufwRules + ` ;;
"delete allow "*/tcp) grep -vx "${3%/tcp}" ` + ufwRules + ` > ` + ufwRules + `.new; mv ` + ufwRules + `.new ` + ufwRules + ` ;;
esac`,
	}
	for name, body := range stubs {
		body = "#!/bin/sh\necho \"" + name + " $*\" >> " + filepath.Join(sb.root, "calls") + "\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(sb.root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{fw, ufwRules} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile("ingress.sh")
	if err != nil {
		t.Fatal(err)
	}
	ports := filepath.Join(sb.root, "run/juist/ingress-ports")
	script := filepath.Join(sb.root, "ingress.sh")
	b = []byte(strings.NewReplacer(ipc.IngressPorts, ports,
		"/var/lib/juist-ingress-ports/", sb.root+"/var/lib/juist-ingress-ports/",
		"/run/juist-ingress-ports.lock", sb.root+"/lock").Replace(string(b)))
	if err := os.WriteFile(script, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(ports), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(action string) {
		t.Helper()
		cmd := exec.Command("/bin/sh", script, action)
		cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ingress.sh %s: %v\n%s", action, err, out)
		}
		sb.calls()
	}
	lines := func(f string) string {
		b, _ := os.ReadFile(f)
		got := strings.Fields(strings.ReplaceAll(string(b), "/tcp", ""))
		slices.Sort(got)
		return strings.Join(got, " ")
	}
	list := func(s string) {
		if err := os.WriteFile(ports, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	check := func(when, firewalld, ufw string) {
		t.Helper()
		if got := lines(fw); got != firewalld {
			t.Errorf("%s, firewalld lets in %q, want %q", when, got, firewalld)
		}
		if got := lines(ufwRules); got != ufw {
			t.Errorf("%s, ufw lets in %q, want %q", when, got, ufw)
		}
	}

	permanent := fw + ".permanent"
	write := func(f, s string) {
		t.Helper()
		if err := os.WriteFile(f, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(permanent, "")
	list("25565\n2222\n80\n443\n41643\nbogus\n0\n70000\n")
	run("ports")
	check("with the ingress not running", "", "")
	write(filepath.Join(sb.root, "active"), "juist-ingress.service\n")
	// Someone else's: open at runtime, and for good.
	write(fw, "8080/tcp\n")
	write(permanent, "8079/tcp\n")
	list("25565\n2222\n8079\n8080\n8081\n80\n443\n41643\nbogus\n0\n70000\n")
	run("ports")
	check("listed", "2222 25565 8080 8081", "2222 25565 8079 8080")
	if got := lines(permanent); got != "2222 25565 8079 8081" {
		t.Errorf("listed, firewalld keeps %q for good", got)
	}
	list("25565\n")
	run("ports")
	check("one withdrawn", "25565 8080", "25565")
	if got := lines(permanent); got != "25565 8079" {
		t.Errorf("one withdrawn, firewalld keeps %q for good", got)
	}
	// A reload takes back what was let in at runtime alone.
	write(fw, "8080/tcp\n")
	run("ports")
	check("after firewalld reloaded", "25565 8080", "25565")
	// Until juistd says, which it does once its view is fresh, as it was.
	if err := os.Remove(ports); err != nil {
		t.Fatal(err)
	}
	run("ports")
	check("juistd's file gone", "25565 8080", "25565")
	write(filepath.Join(sb.root, "elsewhere"), "")
	if err := os.Symlink(filepath.Join(sb.root, "elsewhere"), ports); err != nil {
		t.Fatal(err)
	}
	run("ports")
	check("juistd's file a link", "25565 8080", "25565")
	if err := os.Remove(ports); err != nil {
		t.Fatal(err)
	}
	// A FIFO is no file juistd wrote: nothing waits on it.
	if err := syscall.Mkfifo(ports, 0o644); err != nil {
		t.Fatal(err)
	}
	run("ports")
	check("juistd's file a FIFO", "25565 8080", "25565")
	if err := os.Remove(ports); err != nil {
		t.Fatal(err)
	}
	list("25565\n")
	write(filepath.Join(sb.root, "active"), "")
	run("ports")
	check("the ingress stopped", "8080", "")
	write(filepath.Join(sb.root, "active"), "juist-ingress.service\n")
	run("ports")
	write(filepath.Join(sb.root, "active"), "")
	run("off")
	check("off", "8080", "")
	if got := lines(permanent); got != "8079" {
		t.Errorf("off, firewalld keeps %q for good", got)
	}
	if _, err := os.Stat(filepath.Join(sb.root, "var/lib/juist-ingress-ports")); err == nil {
		t.Error("off left what the script noted")
	}
}

// Two runs at once each let through what they read, and neither takes for
// someone else's what the other let through: they run one after the other.
func TestIngressScriptRunsOneAtATime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress.sh is Linux's, with its flock, timeout and dd")
	}
	sb := newSandbox(t)
	fw := filepath.Join(sb.root, "fw-open")
	slow := `case $1 in --state) exit 0 ;; --permanent) f=` + fw + `.permanent; shift ;; *) f=` + fw + ` ;; esac
sleep 0.05
case $1 in
--query-port=*) grep -qx "${1#--query-port=}" $f 2>/dev/null ;;
--add-port=*) echo "${1#--add-port=}" >> $f ;;
--remove-port=*) grep -vx "${1#--remove-port=}" $f > $f.new; mv $f.new $f ;;
esac`
	if err := os.WriteFile(filepath.Join(sb.root, "bin", "firewall-cmd"), []byte("#!/bin/sh\n"+slow+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ports := filepath.Join(sb.root, "ingress-ports")
	b, err := os.ReadFile("ingress.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(sb.root, "ingress.sh")
	b = []byte(strings.NewReplacer(ipc.IngressPorts, ports,
		"/var/lib/juist-ingress-ports/", sb.root+"/var/lib/juist-ingress-ports/",
		"/run/juist-ingress-ports.lock", sb.root+"/lock").Replace(string(b)))
	for name, data := range map[string]string{script: string(b), ports: "2222\n25565\n", filepath.Join(sb.root, "active"): "juist-ingress.service\n"} {
		if err := os.WriteFile(name, []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() {
			// The second once the first let a port through, before it noted it.
			time.Sleep(time.Duration(i) * 200 * time.Millisecond)
			cmd := exec.Command("/bin/sh", script, "ports")
			cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%v\n%s", err, out)
			}
		})
	}
	wg.Wait()
	if got, _ := os.ReadFile(filepath.Join(sb.root, "var/lib/juist-ingress-ports/opened")); string(got) != "2222\n25565\n" {
		t.Errorf("noted as its own: %q", got)
	}
}

// Removing the package stops an ingress and closes its ports, and takes a
// relay's 443 back.
func TestARemovalStopsTheIngress(t *testing.T) {
	sb := newSandbox(t)
	sb.run("prerm", "remove")
	if calls := sb.calls(); !strings.Contains(calls, "ingress.sh off") || !strings.Contains(calls, "serve.sh off") ||
		!strings.Contains(calls, "relay.sh off") {
		t.Fatalf("prerm left the ingress, the terminator or the relay on 443:\n%s", calls)
	}
}

// The ingress's firewalld service and ufw profile let in the same ports:
// TLS and QUIC on 443, HTTP on 80; an upgrade has ufw take the profile's
// ports anew, which it holds as they were when allowed.
func TestTheIngressProfilesLetQUICIn(t *testing.T) {
	b, err := os.ReadFile("firewalld/juist-ingress.xml")
	if err != nil {
		t.Fatal(err)
	}
	var svc struct {
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			Port     string `xml:"port,attr"`
		} `xml:"port"`
	}
	if err := xml.Unmarshal(b, &svc); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range svc.Ports {
		got = append(got, p.Port+"/"+p.Protocol)
	}
	slices.Sort(got)
	if want := []string{"443/tcp", "443/udp", "80/tcp"}; !slices.Equal(got, want) {
		t.Errorf("firewalld lets in %v, want %v", got, want)
	}
	u, err := os.ReadFile("ufw/juist")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(u), "[juist-ingress]") || !strings.Contains(string(u), "\nports=80,443/tcp|443/udp\n") {
		t.Errorf("ufw's profile:\n%s", u)
	}
	sb := newSandbox(t)
	if err := os.WriteFile(filepath.Join(sb.root, "bin", "ufw"), []byte("#!/bin/sh\necho \"ufw $*\" >> "+
		filepath.Join(sb.root, "calls")+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sb.run("postinst", "configure", "0.9")
	if calls := sb.calls(); !strings.Contains(calls, "ufw app update juist-ingress") {
		t.Errorf("an upgrade left ufw's profile as it was:\n%s", calls)
	}
}

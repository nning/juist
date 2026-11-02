//go:build linux

package conn

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetnsMinecraftJava(t *testing.T) {
	java := os.Getenv("JUIST_TEST_JAVA")
	if java == "" {
		t.Skip("set JUIST_TEST_JAVA to a JDK's java for the Minecraft socket probe")
	}
	lab := newNetnsLab(t)
	a, b := lab.addNode("a", 1), lab.addNode("b", 2)
	multicastNodes(a, b)
	a.start([]*netnsNode{b}, tcpEchoPort)
	b.start([]*netnsNode{a}, 0)
	lab.must(lab.exec(b, "nft", "add table ip lan; add chain ip lan pre { type filter hook prerouting priority -300; }; add rule ip lan pre iifname "+b.veth+" udp dport 4445 drop"))
	source := filepath.Join(t.TempDir(), "LanProbe.java")
	if err := os.WriteFile(source, []byte(lanProbeJava), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := lab.exec(b, java, source)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	lines := make(chan string, 2)
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		done <- cmd.Wait()
	}()
	select {
	case line := <-lines:
		if line != "READY" {
			t.Fatalf("java: %s", line)
		}
	case err := <-done:
		t.Fatalf("java: %v: %s", err, stderr.String())
	case <-time.After(30 * time.Second):
		t.Fatal("java did not become ready")
	}
	deadline := time.After(30 * time.Second)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			a.command("SEND minecraft 65 routed", "OK")
		case line := <-lines:
			if !strings.HasPrefix(line, "CONNECTED 100.64.0.1:45111") {
				t.Fatalf("java: %s", line)
			}
			if err := <-done; err != nil {
				t.Fatalf("java: %v: %s", err, stderr.String())
			}
			return
		case err := <-done:
			if err != nil {
				t.Fatalf("java: %v: %s", err, stderr.String())
			}
			select {
			case line := <-lines:
				if !strings.HasPrefix(line, "CONNECTED 100.64.0.1:45111") {
					t.Fatalf("java: %s", line)
				}
				return
			default:
				t.Fatal("java exited without connecting")
			}
		case <-deadline:
			t.Fatal("java did not discover and connect to the world")
		}
	}
}

const lanProbeJava = `import java.net.*;
import java.nio.charset.StandardCharsets;

public class LanProbe {
    public static void main(String[] args) throws Exception {
        try (MulticastSocket socket = new MulticastSocket(4445)) {
            socket.joinGroup(InetAddress.getByName("224.0.2.60"));
            socket.setSoTimeout(15000);
            System.out.println("READY");
            byte[] buffer = new byte[1500];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);
            String message = new String(buffer, 0, packet.getLength(), StandardCharsets.UTF_8);
            if (!message.contains("[MOTD]juist test[/MOTD]")) throw new Exception("bad MOTD");
            int start = message.indexOf("[AD]") + 4;
            int port = Integer.parseInt(message.substring(start, message.indexOf("[/AD]", start)));
            try (Socket game = new Socket()) {
                game.connect(new InetSocketAddress(packet.getAddress(), port), 10000);
                game.setSoTimeout(10000);
                game.getOutputStream().write(106);
                if (game.getInputStream().read() != 106) throw new Exception("no echo");
            }
            System.out.println("CONNECTED " + packet.getAddress().getHostAddress() + ":" + port);
        }
    }
}
`

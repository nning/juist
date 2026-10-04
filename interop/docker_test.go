//go:build interop && linux

package interop

import (
	"strings"
	"testing"
	"time"
)

// containerMember is the service member as its image runs it, beside a
// service on a Docker network of its own with no way out, which it publishes
// through fb with a certificate from Pebble; what that service reaches of the
// host and the LAN is measured and logged.
func containerMember(t *testing.T, fb, lx *vm, image string) {
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := lx.try("docker logs --tail 40 svcm 2>&1; docker exec svcm juist -s /var/lib/juist/daemon.sock status", time.Minute)
			t.Logf("the service member in its container:\n%s", out)
			hold(t, fb, lx)
		}
		lx.try("docker rm -f svcm backend; docker network rm svcnet juistnet", time.Minute)
	})
	lx.put(t, image, "/tmp/juist-image.tar", 0o644)
	lx.run(t, `set -e
if ! command -v docker >/dev/null; then
	apt-get update -q >/dev/null
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io >/dev/null
fi
docker load -q -i /tmp/juist-image.tar >/dev/null`)
	t.Logf("docker %s", strings.TrimSpace(lx.run(t, "docker version --format '{{.Server.Version}}'")))
	tag := strings.TrimSpace(lx.run(t, `docker image ls --format '{{.Repository}}:{{.Tag}}' juist | head -1`))
	lx.run(t, `set -e
docker network create --internal svcnet >/dev/null
docker network create juistnet >/dev/null
docker run -d --name backend --network svcnet -v /tmp/probe:/probe:ro --entrypoint /probe `+tag+` serve web-in-docker 8080 >/dev/null
docker run -d --name svcm --network juistnet -v /etc/juist-test-ca.pem:/ca.pem:ro -e SSL_CERT_FILE=/ca.pem `+tag+` \
  --serve dweb=backend:8080 --no-dht --acme https://`+fb.lanAddr+`:14000/dir >/dev/null
docker network connect svcnet svcm`)
	lx.eventually(t, "the service member answering", time.Minute, "docker exec svcm juist -s /var/lib/juist/daemon.sock status",
		func(string) bool { return true })
	invite(t, fb, lx, "docker exec svcm juist -s /var/lib/juist/daemon.sock join '%s' --name dweb")
	fb.run(t, `set -e
juist grant dweb service
juist publish add dweb dweb 443`)
	fb.eventually(t, "fetching the container's name through itself", 4*time.Minute,
		"/tmp/probe hello "+fb.lanAddr+":443 dweb.pub.example.org /tmp/root.pem", has("web-in-docker from "))

	// What a service on the internal network reaches: the host at the
	// network's gateway, the LAN, and the overlay through the member.
	gw := strings.TrimSpace(lx.run(t, `docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' svcnet`))
	fb4 := strings.TrimSpace(lx.run(t, `juist devices | awk '$1 == "fb" {print $2}'`))
	for _, target := range []string{gw + ":22", fb.lanAddr + ":14000", fb4 + ":41644"} {
		out, err := lx.try(`timeout 20 docker run --rm --network svcnet -v /tmp/probe:/probe:ro --entrypoint /probe `+tag+
			` get `+target, time.Minute)
		t.Logf("from the internal network, %s: reached %v: %s", target, err == nil, strings.TrimSpace(out))
		if err == nil && target != gw+":22" {
			t.Errorf("a service on the internal network reached %s", target)
		}
	}
}

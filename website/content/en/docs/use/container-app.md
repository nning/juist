---
title: An app in a container
linkTitle: An app in a container
description: Make an app in Docker or Podman a device of its own in your network, through a juist container that shares its network namespace, with its own addresses and its own place in the access policy.
lead: An app in a container should reach your network, while the host it runs on and its other containers stay out of it. A juist container beside it, sharing its network namespace, makes the app a device of its own.
---

## What you get

juistd runs in a second container that shares the app's network namespace
and makes `juist0` there. Whatever the app opens to a member's address goes
through the tunnel, from the device's own addresses. The
[access policy]({{< relref "docs/access" >}}) treats the app as any other
device, so it can be given exactly what it needs and nothing else. The host
and its other containers stay outside the network.

## What you need

- A Linux host with Docker or Podman.
- The juist image: `make image` in the source tree, then `docker load`.

## Setting it up

{{< step on="an admin's device" >}}
Invite the device:

```sh
juist invite app
```
{{< /step >}}

{{< step on="the container host" >}}
In a `compose.yaml`, a service of its own, `netns`, holds the namespace, so
that juist and the app keep it when either restarts. Pass the invite link in
`JUIST_JOIN`:

```yaml
services:
  netns:
    image: registry.k8s.io/pause:3.10
    restart: unless-stopped
  juist:
    image: juist:VERSION
    network_mode: service:netns
    user: "0:0"
    cap_drop: [ALL]
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun]
    environment:
      JUIST_JOIN: "juist:…"
    volumes:
      - type: volume
        source: juist
        target: /var/lib/juist
        volume:
          nocopy: true
    restart: unless-stopped
  app:
    image: …   # the app
    network_mode: service:netns
    depends_on: [juist]
    restart: unless-stopped
volumes:
  juist: {}
```

```sh
docker compose up -d
```

`docker compose logs juist` shows how the join went, and
`docker compose exec juist juist status` the device's addresses. With
Podman, add the example's `compose.podman.yaml`.
{{< /step >}}

{{< step on="an admin's device" >}}
Give the app only what it needs, for example Ollama on `mac`:

```text
pass from app to mac proto tcp port 11434
```

See [Access policy]({{< relref "docs/access" >}}) for how to set it.
{{< /step >}}

## Watch out for

- **Names do not resolve in the containers**, which run no systemd-resolved,
  and `juist health` says so. Use the addresses `juist devices` lists, or put
  names into the namespace's `/etc/hosts` with `extra_hosts` on `netns`,
  with the IPv6 address, which renumbering does not change.
- **Restart together.** If `netns` restarts, `docker compose restart netns`
  restarts juist and the app with it; they are left in its old namespace
  otherwise.
- **No privileged mode.** juistd needs `CAP_NET_ADMIN` and `/dev/net/tun`
  alone. Docker gives a capability to root only, so juistd runs as root
  there, with no other capability.
- **Ports the app publishes** go on `netns`, whose namespace it is.
- **Without an access policy** the app reaches every port of every member,
  like any other device.

## Read more

- [In a container]({{< relref "docs/install" >}}#in-a-container), in the
  installation guide
- [examples/sidecar](https://github.com/nning/juist/tree/main/examples/sidecar),
  the same with comments, an `.env` and Podman's override

---
title: Service members
linkTitle: Service members
description: Publish a server you do not trust inside your network, through a separate juistd that no device accepts connections from.
lead: A server published from a full member can reach your network once someone breaks into it. A service member publishes it from outside your network instead.
status: [Linux, FreeBSD]
---

## How it works

A **service member** is a separate, unprivileged juistd next to the service.
It publishes the service's names like any member, but no device accepts
connections it opens. Only its replies get through. It makes no network device
on the host.

The service member ends TLS itself, with a certificate from Let's Encrypt. It
answers only for the names it publishes and for log sync. It holds no other
role.

You need a domain and an ingress, as
[Publishing services]({{< relref "docs/publishing" >}}#setting-it-up) sets them
up. The example publishes Immich as `immich.example.org`.

## Setting it up

{{< step on="an admin's device" >}}
```sh
juist invite immich --service immich
```

This admits a new device named `immich` as a service member that publishes
`immich.example.org`, and prints the link to join with.
{{< /step >}}

{{< step on="the server" as="the service member" >}}
In Docker, add the service member to Immich's Compose project. Put a
`docker-compose.override.yml` next to Immich's `docker-compose.yml`; Compose
reads both. It makes Immich's network internal, so that the service member is
its only way in or out, and removes the port `immich-server` publishes. The
image comes from `make image` in the source tree, followed by `docker load`:

```yaml
services:
  immich-server:
    ports: !reset []
  juist:
    image: juist:VERSION
    command: ["--serve", "immich=immich-server:2283"]
    environment:
      JUIST_JOIN: "juist:…"
    volumes:
      - juist:/var/lib/juist
    networks: [default, out]
    restart: unless-stopped
networks:
  default:
    internal: true
    driver_opts:
      com.docker.network.bridge.gateway_mode_ipv4: isolated
  out: {}
volumes:
  juist: {}
```

```sh
docker compose down && docker compose up -d
```

The `down` is required: Compose does not change a network that exists, and may
not say so. `!reset` needs Compose 2.24 or later.

The service member joins with the link and ignores it once in the network.
`docker compose logs juist` shows how the join went, including the words to
compare if the invite asks for them.
{{< /step >}}

A complete Compose file with a web service to try it on, for Docker and
Podman, is in
[examples/service-member](https://github.com/nning/juist/tree/main/examples/service-member).

## Without Docker

A service member is juistd run as any user. It needs no root:

```sh
juistd --home ~/immich-juist --serve immich=127.0.0.1:2283 --join 'juist:…'
```

`--home` holds its keys and the log. It joins with the link the first time and
ignores it later. What it prints is its log, so run it under your service
manager, for example as a systemd user unit. `--serve @=web:80` serves the
domain itself.

## Good to know

- The service has no internet access. If it downloads things on first start,
  or on first use, do that beforehand.
- Docker 29's isolated gateway mode also cuts the service off from the host.
  Without it, the service reaches anything on the host that listens on all
  addresses. Podman has no gateway mode: drop `driver_opts` there.
- `--serve NAME=ADDR --http3` offers HTTP/3, `--members` makes the name
  [members-only]({{< relref "docs/members-only" >}}), and
  `--serve status=status-page:all` serves the
  [status page]({{< relref "docs/publishing" >}}#status-page).
- The CAA record for its names is in its log
  ([why it matters]({{< relref "docs/publishing" >}}#protecting-the-certificate)).
- `juist revoke immich service` makes it an ordinary member again, with a
  warning. Remove a device that may be compromised with `juist remove`
  instead.

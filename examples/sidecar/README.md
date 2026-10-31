# An app in a container, as a device of its own

```
app ───┐
       ├── netns's network namespace ── juist0 ──juist──▶ the other members
juist ─┘
```

The app and juistd share a network namespace, held by a container that does
nothing else. juistd makes `juist0` in it, so whatever the app opens to a
member's address goes through the tunnel, from the device's own addresses,
and the access policy treats it as it treats any device. A
[service member](../service-member) only accepts connections for the names it
publishes; this is a member like any other, and the app connects out.

## Run it

1. Build the image, in the repository's root:

   ```sh
   make image
   docker load -i build/image/juist-*-amd64.tar   # Loaded image: juist:VERSION
   ```

2. On an admin's device, invite the device:

   ```sh
   juist invite app
   ```

   It names the device `app` and waits.

3. Here, `cp .env.example .env`, set `JUIST_IMAGE` to the loaded image and
   `JUIST_JOIN` to the link, then:

   ```sh
   docker compose up -d
   docker compose logs -f juist   # until: joined "NETWORK" as app
   ```

   The log shows the words the admin's device asks to compare. Once joined,
   the link is spent and `JUIST_JOIN` ignored.

4. `docker compose exec juist juist devices` lists the members' addresses;
   the app reaches them: `docker compose exec app wget -qO- http://198.18.0.1/`.

An [access policy](../../website/content/en/docs/access.md) gives the device
only what the app needs, as Ollama on `mac`:

```
pass from app to mac proto tcp port 11434
```

For an app of your own, replace `app` and keep `network_mode: service:netns`;
ports it publishes go on `netns`, whose namespace it is. An app that already
shares another container's namespace, such as a Tailscale container's, takes
juist into that one, `network_mode: service:tailscale`, with no `netns`.

## Limits

- **Names.** `DEVICE.NETWORK.juist` does not resolve in the containers: no
  systemd-resolved runs there, and the namespace's resolv.conf is Docker's.
  `juist health` says `warning: NETWORK.juist not resolved here: systemd-resolved
  does not run on this host`. Use addresses, or give names in `netns`'s
  `extra_hosts`, which the app shares, with the IPv6 address, which renumbering
  does not change: `extra_hosts: ["mac.home.juist=fd7e:…"]`.
- **Rights.** juistd needs `CAP_NET_ADMIN` and `/dev/net/tun`, not
  `privileged`. Docker gives a capability to root alone, so juistd runs as root
  in its container, with no other capability, and its volume is root's
  (`nocopy`), not the image's user's, which juistd would refuse.
- **Restarts.** juist and the app keep the namespace across their own
  restarts; a restarted juist is back in about ten seconds. A restarted `netns`
  leaves them in its old namespace: `docker compose restart netns` restarts
  them with it, and `docker compose up -d` does after any other restart.
- **LAN discovery.** juistd looks for members on `netns`'s Docker network as on
  any LAN; `command: ["--no-discovery"]` turns that off.
- **tailscaled** in the namespace, in userspace mode (`TS_USERSPACE=true`),
  holds no device, route or firewall rule, so the two do not meet: the app
  reaches the tailnet through tailscaled's proxy, where one is set, and the
  juist network through `juist0`.

To take it down: `juist remove app` on the admin's device, then
`docker compose down -v`, which deletes the device's keys with the volume.

## Podman

Set `COMPOSE_FILE=compose.yaml:compose.podman.yaml` in `.env`: Podman gives
the capability to the image's own user, so juistd runs as that user, not as
root. `podman load` names the image `localhost/juist:VERSION`.

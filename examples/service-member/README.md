# A service behind a juist service member

```
browser ──TLS──▶ ingress ──juist──▶ juist container (TLS ends) ──HTTP──▶ whoami:80
```

`whoami` is on an internal network with the service member alone: it has no
way out, publishes no port, and with Docker 29's isolated gateway mode cannot
reach the host. The service member, `juistd --serve whoami=whoami:80`, ends
TLS for `whoami.DOMAIN` with a certificate from Let's Encrypt; every member
keeps it from opening a connection to them. See
[Publishing services](../../website/content/en/docs/publishing.md) for the design.

It needs a network with a domain (`juist network domain DOMAIN`) and an
ingress whose address `*.DOMAIN` points at.

## Run it

1. Build the image, in the repository's root:

   ```sh
   make image
   docker load -i build/image/juist-*-amd64.tar   # Loaded image: juist:VERSION
   ```

2. On an admin's device, invite the service member:

   ```sh
   juist invite whoami --service whoami
   ```

   It names the device `whoami`, publishes `whoami.DOMAIN` on it, and waits.

3. Here, `cp .env.example .env`, set `JUIST_IMAGE` to the loaded image and
   `JUIST_JOIN` to the link, then:

   ```sh
   docker compose up -d
   docker compose logs -f juist   # until: joined "NETWORK" as whoami
   ```

   The log shows the words the admin's device asks to compare. Once joined,
   the link is spent and `JUIST_JOIN` ignored.

4. From anywhere: `curl https://whoami.DOMAIN/`. The first request has the
   certificate issued, which takes a few seconds.

To take it down: `juist remove whoami` on the admin's device, then
`docker compose down -v`, which deletes the device's keys with the volume.

## Podman

Set `COMPOSE_FILE=compose.yaml:compose.podman.yaml` in `.env`: Podman refuses
Docker's gateway mode, and rootless needs none. `podman load` names the image
`localhost/juist:VERSION`.

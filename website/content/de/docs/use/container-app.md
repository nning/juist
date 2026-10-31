---
title: Eine App im Container
linkTitle: Eine App im Container
description: Eine App in Docker oder Podman zu einem eigenen Gerät deines Netzes machen, über einen juist-Container, der sich ihren Netz-Namespace teilt, mit eigenen Adressen und eigenem Platz in den Zugriffsregeln.
lead: Eine App im Container soll dein Netz erreichen, der Host, auf dem sie läuft, und seine anderen Container aber draußen bleiben. Ein juist-Container daneben, der sich ihren Netz-Namespace teilt, macht die App zu einem eigenen Gerät.
---

## Was du bekommst

juistd läuft in einem zweiten Container, der sich den Netz-Namespace der App
teilt, und legt dort `juist0` an. Was die App zu einer Adresse eines
Mitglieds öffnet, geht durch den Tunnel, von den eigenen Adressen des
Geräts. Die [Zugriffsregeln]({{< relref "docs/access" >}}) behandeln die App
wie jedes andere Gerät, du kannst ihr also genau das geben, was sie braucht,
und nichts sonst. Der Host und seine anderen Container bleiben außerhalb des
Netzes.

## Was du brauchst

- Einen Linux-Host mit Docker oder Podman.
- Das Image von juist: `make image` im Quellbaum, dann `docker load`.

## Einrichten

{{< step on="dem Gerät eines Admins" >}}
Lade das Gerät ein:

```sh
juist invite app
```
{{< /step >}}

{{< step on="dem Container-Host" >}}
In einer `compose.yaml` hält ein eigener Dienst, `netns`, den Namespace,
damit juist und die App ihn behalten, wenn einer von beiden neu startet. Den
Einladungslink bekommt juist in `JUIST_JOIN`:

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
    image: …   # die App
    network_mode: service:netns
    depends_on: [juist]
    restart: unless-stopped
volumes:
  juist: {}
```

```sh
docker compose up -d
```

Wie der Beitritt lief, zeigt `docker compose logs juist`, die Adressen des
Geräts `docker compose exec juist juist status`. Unter Podman kommt die
`compose.podman.yaml` des Beispiels dazu.
{{< /step >}}

{{< step on="dem Gerät eines Admins" >}}
Gib der App nur, was sie braucht, etwa Ollama auf `mac`:

```text
pass from app to mac proto tcp port 11434
```

Wie du das festlegst, steht unter
[Zugriffsregeln]({{< relref "docs/access" >}}).
{{< /step >}}

## Darauf achten

- **Namen werden in den Containern nicht aufgelöst**, da dort kein
  systemd-resolved läuft, und `juist health` sagt das. Nimm die Adressen, die
  `juist devices` auflistet, oder trag Namen mit `extra_hosts` an `netns`
  in die `/etc/hosts` des Namespace ein, mit der IPv6-Adresse, die beim
  Umnummerieren gleich bleibt.
- **Gemeinsam neu starten.** Startet `netns` neu, startet `docker compose
  restart netns` juist und die App mit ihm neu; sonst bleiben sie in seinem
  alten Namespace.
- **Kein privilegierter Modus.** juistd braucht nur `CAP_NET_ADMIN` und
  `/dev/net/tun`. Docker gibt eine Capability nur root, also läuft juistd dort
  als root, ohne jede andere Capability.
- **Ports, die die App veröffentlicht**, gehören an `netns`, denn es ist
  dessen Namespace.
- **Ohne Zugriffsregeln** erreicht die App jeden Port jedes Mitglieds, wie
  jedes andere Gerät.

## Weiterlesen

- [Im Container]({{< relref "docs/install" >}}#im-container), in der
  Installationsanleitung
- [examples/sidecar](https://github.com/nning/juist/tree/main/examples/sidecar),
  dasselbe mit Kommentaren, einer `.env` und Podmans Ergänzung

---
title: Service-Mitglieder
linkTitle: Service-Mitglieder
description: Einen Server veröffentlichen, dem du in deinem Netz nicht traust, über ein eigenes juistd, von dem kein Gerät Verbindungen annimmt.
lead: Ein Server, den ein vollwertiges Mitglied veröffentlicht, erreicht dein Netz, sobald jemand in ihn einbricht. Ein Service-Mitglied veröffentlicht ihn stattdessen von außerhalb deines Netzes.
status: [Linux, FreeBSD]
---

## So funktioniert es

Ein **Service-Mitglied** ist ein eigenes, unprivilegiertes juistd neben dem
Dienst. Es veröffentlicht die Namen des Dienstes wie jedes Mitglied, aber kein
Gerät nimmt Verbindungen an, die es öffnet. Nur seine Antworten kommen durch.
Es legt auf dem Host kein Netzwerkgerät an.

Das Service-Mitglied beendet TLS selbst, mit einem Zertifikat von Let's
Encrypt. Es antwortet nur für die Namen, die es veröffentlicht, und für den
Log-Abgleich. Eine weitere Rolle hat es nicht.

Du brauchst eine Domain und einen Ingress, wie sie
[Dienste veröffentlichen]({{< relref "docs/publishing" >}}#setting-it-up)
einrichtet. Das Beispiel veröffentlicht Immich als `immich.example.org`.

## Einrichten

{{< step on="dem Gerät eines Admins" >}}
```sh
juist invite immich --service immich
```

Das nimmt ein neues Gerät namens `immich` als Service-Mitglied auf, das
`immich.example.org` veröffentlicht, und gibt den Link zum Beitreten aus.
{{< /step >}}

{{< step on="dem Server" as="dem Service-Mitglied" >}}
Unter Docker kommt das Service-Mitglied in das Compose-Projekt von Immich. Leg
eine `docker-compose.override.yml` neben Immichs `docker-compose.yml`; Compose
liest beide. Sie macht Immichs Netz intern, damit das Service-Mitglied sein
einziger Weg hinein und hinaus ist, und entfernt den Port, den
`immich-server` veröffentlicht. Das Image baust du mit `make image` im
Quellbaum und lädst es mit `docker load`:

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

Das `down` ist nötig: Ein bestehendes Netz ändert Compose nicht, womöglich
ohne es zu sagen. `!reset` braucht Compose 2.24 oder neuer.

Das Service-Mitglied tritt mit dem Link bei und ignoriert ihn danach. Wie der
Beitritt lief, zeigt `docker compose logs juist`, samt den Wörtern zum
Vergleichen, wenn die Einladung danach fragt.
{{< /step >}}

Eine vollständige Compose-Datei mit einem Webdienst zum Ausprobieren, für
Docker und Podman, liegt in
[examples/service-member](https://github.com/nning/juist/tree/main/examples/service-member).

## Ohne Docker

Ein Service-Mitglied ist ein juistd unter einem beliebigen Benutzer. Es
braucht kein root:

```sh
juistd --home ~/immich-juist --serve immich=127.0.0.1:2283 --join 'juist:…'
```

In `--home` liegen seine Schlüssel und das Log. Beim ersten Start tritt es mit
dem Link bei, danach ignoriert es ihn. Was es ausgibt, ist sein Log: Starte es
deshalb über deinen Dienstverwalter, etwa als systemd-Benutzer-Unit.
`--serve @=web:80` veröffentlicht die Domain selbst.

## Gut zu wissen

- Der Dienst hat keinen Zugang ins Internet. Lädt er beim ersten Start oder
  beim ersten Gebrauch etwas herunter, erledige das vorher.
- Der isolierte Gateway-Modus von Docker 29 trennt den Dienst auch vom Host.
  Ohne ihn erreicht der Dienst alles auf dem Host, was auf allen Adressen
  lauscht. Podman kennt keinen Gateway-Modus: Dort entfallen die
  `driver_opts`.
- `--serve NAME=ADDR --http3` bietet HTTP/3 an, `--members` macht den Namen
  zu einem [Namen nur für Mitglieder]({{< relref "docs/members-only" >}}), und
  `--serve status=status-page:all` bietet die
  [Statusseite]({{< relref "docs/publishing" >}}#status-page) an.
- Den CAA-Eintrag für seine Namen findest du in seinem Log
  ([warum er wichtig ist]({{< relref "docs/publishing" >}}#protecting-the-certificate)).
- `juist revoke immich service` macht es wieder zu einem gewöhnlichen
  Mitglied, mit einer Warnung. Ein womöglich kompromittiertes Gerät entfernst
  du stattdessen mit `juist remove`.

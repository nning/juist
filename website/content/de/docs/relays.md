---
title: Relays, Ports und Firewalls
linkTitle: Relays und Ports
description: Ein Relay für Geräte einrichten, die sich nicht direkt erreichen, die richtigen Ports öffnen und ohne öffentliche Helfer auskommen.
lead: Können sich zwei Geräte nicht direkt erreichen, leitet ein Mitglied deines eigenen Netzes ihren Verkehr weiter. Außerdem erfährst du hier, welche Ports juist nutzt und was du wo öffnen musst.
---

## Was ein Relay tut

Meist bekommt juist einen direkten Tunnel durch NAT hin. Das scheitert nur,
wenn beide Geräte hinter symmetrischem NAT stehen, einer strengen Variante,
die für jedes Ziel einen neuen Port wählt. Dann brauchen die beiden ein
Relay.

Ein Relay ist ein Mitglied mit öffentlicher Adresse, etwa ein VPS, das
Verkehr zwischen Geräten weiterleitet, die sich nicht direkt erreichen. Fremde
leiten deinen Verkehr nie weiter. Nur Mitglieder können das Relay nutzen, und
es sieht nur verschlüsselten WireGuard-Verkehr.

Ein Relay hilft auch bei Einladungen. Rufst du `juist invite` auf einem
Laptop hinter NAT auf, wartet die Einladung zusätzlich beim Relay, und der
Link nennt das Relay. So kann ein neues Gerät von überall beitreten
([Einladungen]({{< relref "docs/invites" >}})). Das Geheimnis der Einladung
bekommt das Relay nie zu sehen.

## Ein Relay einrichten

{{< step on="vps" as="dem Relay" >}}
Tritt dem Netz bei und öffne dann die Ports mit ufw:

```sh
sudo juist join 'juist:…'
sudo ufw allow juist && sudo ufw allow juist-relay
```

Oder mit firewalld:

```sh
sudo firewall-cmd --permanent --add-service=juist --add-service=juist-relay && sudo firewall-cmd --reload
```
{{< /step >}}

{{< step on="dem Gerät eines Admins" >}}
Gib dem VPS die [Rolle]({{< relref "docs/how-it-works" >}}#roles) `relay`:

```sh
juist grant vps relay
```

In der Zeile `Relays` von `juist status` zählt der VPS dann als verfügbar.
{{< /step >}}

Mit `juist revoke vps relay` entziehst du die Rolle wieder. Am besten gibst
du sie zwei oder mehr Geräten mit öffentlicher Adresse. In einem Netz mit
mehr als zwei Geräten warnt `juist health`, solange kein Gerät Relay sein
darf.

## Ein Relay auf 443

Ein Relay kann auch einen öffentlichen Namen auf Port 443 bedienen, wie jeder
HTTPS-Server. Ein Gerät in einem Netz, das nichts anderes hinauslässt,
erreicht das Relay dort, entweder von selbst oder im
[Nur-HTTPS-Modus]({{< relref "docs/https-only" >}}).

{{< step on="deinem DNS" >}}
Lass einen Namen wie `relay.example.org` auf das Relay zeigen, mit einem
A-Eintrag und, falls das Relay IPv6 hat, einem AAAA-Eintrag.
{{< /step >}}

{{< step on="vps" as="dem Relay" >}}
Lass das Relay den Namen bedienen:

```sh
sudo juist set --relay-name relay.example.org
```

juistd belegt 443/tcp an den Adressen des Relays, ufw oder firewalld lassen
es durch, und Let's Encrypt stellt ein Zertifikat für den Namen aus.
`juist status` sagt dann:

```console
  Relay name    relay.example.org, on 443
```
{{< /step >}}

- Jedes Gerät erfährt den Namen aus der Ankündigung des Relays.
- Port 443 braucht ein Recht, das nur root vergeben kann. `sudo juist set`
  gibt juistd `CAP_NET_BIND_SERVICE` nur dafür, per systemd-Drop-in.
  `sudo juist set --relay-name ""` nimmt es mit dem Namen zurück.
- Unter FreeBSD belegt der Helfer von juistd Port 443 nur, solange root es
  erlaubt und kein anderes Programm auf 443 lauscht. Läuft pf, muss es den
  Verkehr durchlassen.
- Ist der Name weg, das Recht aber noch da, warnt `juist health`, und
  `juist reset` nimmt das Recht zurück.
- Die Mitglieder nutzen den Namen erst, wenn der Server dort belegt, dass er
  dieses Relay ist.
- Ist das Relay zugleich der [Ingress]({{< relref "docs/publishing" >}})
  des Netzes, belegt der Ingress 443 und reicht die Verbindungen für den
  Namen an das Relay weiter. Ohne `--relay-name` bedient es `relay.DOMAIN`,
  auf das der Wildcard-Eintrag der Domain schon zeigt. `relay` lässt sich
  dann nicht veröffentlichen.
- Sind mehrere Ingresse Relays, übernimmt einer `relay.DOMAIN`, wie
  `juist status` dort sagt. Gib den anderen eigene Namen und lass
  `relay.DOMAIN` nur auf diesen einen zeigen.
- Ein CAA-Eintrag für den Namen muss Let's Encrypt zulassen.
- Auf einem Gerät in mehreren Netzen bedient nur der juistd des ersten Netzes
  einen Namen auf 443.

## Ports

| Port | Wofür | Wo öffnen |
|---|---|---|
| 41643/udp | WireGuard und Pfadsuche | auf einem Gerät mit öffentlicher Adresse |
| 41645/tcp, 41645/udp | das Relay und die STUN-Antworten, mit denen Mitglieder es vermessen | auf einem Gerät mit der Rolle `relay` |
| 443/tcp | das Relay unter seinem öffentlichen Namen | auf einem Relay mit Namen; `juist set --relay-name` öffnet ihn |
| 41642/tcp | eine Einladung per Code im LAN annehmen | auf dem einladenden Gerät, solange `juist invite` läuft |
| 443/tcp, 443/udp, 80/tcp | die Namen, die Geräte veröffentlichen, per TLS und QUIC | auf einem Gerät mit der Rolle `ingress`; `juist ingress serve` öffnet sie |
| die Ports, auf denen Namen per TCP veröffentlicht sind | diese Namen | auf jedem Ingress; er öffnet und schließt sie, wenn Namen hinzukommen oder wegfallen |

Hinter NAT musst du nichts öffnen. Auch eine Einladung per Link braucht
keinen offenen Port: Erreicht das neue Gerät das einladende nicht direkt,
treffen sich die beiden sofort über ein Relay oder nach etwa einer Minute
über den öffentlichen DHT.

Ein Gerät in [mehreren Netzen]({{< relref "docs/networks" >}}) betreibt für
jedes Netz einen eigenen juistd. Der n-te juistd nutzt die obigen Ports plus 10·n,
zum Beispiel 41653/udp für `juistd@juist1`.

## Firewalls

Die Pakete bringen Profile für ufw und firewalld mit, die `juist`,
`juist-relay`, `juist-relay-443`, `juist-invite` und `juist-ingress` heißen. Sie enthalten die
Ports des ersten Netzes. Die Ports der anderen Netze nennt `juist status`.

Der Log-Abgleich läuft im Tunnel, über TCP 41644 auf `juist0` (41654 auf
`juist1` und so weiter). Läuft ufw oder firewalld, lassen die Pakete ihn
durch. Eine von Hand eingerichtete Firewall muss ihn ebenfalls durchlassen.
Sonst behält das Gerät seine Tunnel, verpasst aber Änderungen am Netz, auch
das Entfernen von Geräten, und `juist health` meldet das. Ein
[Exit-Node]({{< relref "docs/exit-nodes" >}}) beantwortet dort außerdem DNS,
auf UDP und TCP 41646.

{{< note >}}
Beim Upgrade von einem Build, dessen Profil `juist` noch alle Ports öffnete:
ufw behält die alten Ports, bis du `sudo ufw app update juist` ausführst.
firewalld beschränkt `juist` dagegen sofort auf 41643/udp. In beiden Fällen
braucht ein Relay zusätzlich `juist-relay`.
{{< /note >}}

## Ohne öffentliche Helfer

In der Voreinstellung fragt juistd öffentliche STUN-Server (Google,
Cloudflare) nach seiner öffentlichen Adresse. Außerdem nutzt es den
öffentlichen BitTorrent-DHT, ein gemeinsames Verzeichnis im Internet, um
Mitglieder wiederzufinden, die es aus den Augen verloren hat. Beide sehen nur
Adressen, nie Inhalte.

Mit einem eigenen Relay kommt das Netz ohne beide aus. Führe dazu auf jedem
Gerät Folgendes aus:

```sh
sudo systemctl edit juistd
```

und trag Folgendes ein:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/juistd --home /var/lib/juist --socket /run/juist/juistd.sock --tun juist0 --no-dht --no-stun
```

Die Geräte finden sich dann im LAN und über Mitglieder, die sie schon
kennen. Das Relay teilt jedem Gerät seine öffentliche Adresse mit, und
Einladungen per Link laufen darüber. `man juistd` beschreibt alle Optionen.

## Fehlersuche

| `juist health` meldet | Was du tun kannst |
|---|---|
| `no tunnel traffic from …` | Öffne 41643/udp auf einem Gerät mit öffentlicher Adresse, oder gib einem Gerät die Rolle `relay`. |
| `no device reaches this relay` | Öffne 41645/tcp und udp auf dem Relay, auch in jeder vorgeschalteten Firewall. |
| `no device may relay` | Gib einem Gerät mit öffentlicher Adresse die Rolle: `juist grant DEVICE relay`. |
| `no certificate for relay.example.org yet` | Lass den Namen auf das Relay zeigen und 443/tcp zu ihm durch. |
| `the relay cannot take 443` | Ein anderes Programm belegt dort 443, oder juistd fehlt das Recht, das `juist set` vergibt. |
| `members are not told of …: this device does not relay` | Gib dem Gerät die Rolle `relay`: `juist grant DEVICE relay`. |
| `log sync … fails in the tunnel` | Lass `juist0` durch die Firewall des anderen Geräts, wie der Hinweis vorschlägt. |
| `no answer from …` | Das Gerät ist offline, oder sein Port 41643/udp ist gesperrt. |

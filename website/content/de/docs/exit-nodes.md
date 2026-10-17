---
title: Exit-Nodes
linkTitle: Exit-Nodes
description: Den Internetverkehr eines Geräts über ein anderes Mitglied des Netzes leiten, und ein Mitglied diesen Verkehr für die anderen übernehmen lassen.
lead: Ein Exit-Node ist ein Gerät in deinem Netz, über das die anderen ins Internet gehen. Im Café geht dein Laptop dann über deinen VPS ins Internet statt über das WLAN des Cafés.
---

## So funktioniert es

Normalerweise geht ein Gerät dort ins Internet, wo es sich gerade befindet.
Mit einem Exit-Node schickt es seinen Internetverkehr zuerst durch den Tunnel
zu einem anderen Mitglied, also zu einem anderen Gerät in deinem Netz
([So funktioniert juist]({{< relref "docs/how-it-works" >}})). Dieses
Mitglied leitet den Verkehr weiter. Webseiten sehen dann die Adresse des
Exit-Nodes, und das WLAN des Cafés sieht nur verschlüsselten Verkehr.

Ein Gerät wird in zwei Schritten zum Exit-Node. Zuerst gibt ein Admin, also
eine Person, deren Schlüssel Änderungen am Netz bestätigt, dem Gerät die
Rolle `exit`. Eine Rolle ist eine Berechtigung, die das Netz für ein Gerät
festhält. Dann stimmt der [Operator]({{< relref "docs/operator" >}}) des
Geräts zu, also der lokale Benutzer, der es ohne sudo verwaltet, indem er
dort `juist exit serve` ausführt.

Ob ein Gerät einen Exit-Node nutzt, entscheidet es selbst. Solange du auf
einem Gerät nicht `juist exit use` ausführst, ändert sich dort nichts.

## Einen Exit-Node einrichten

{{< step on="dem Gerät eines Admins" >}}
Gib dem VPS die Rolle:

```sh
juist grant vps exit
```

Braucht eine Änderung mehr als einen Admin, wartet sie auf die anderen
([wie Änderungen bestätigt werden]({{< relref "docs/admins" >}})).
{{< /step >}}

{{< step on="vps" as="dem Exit-Node" >}}
Stimm zu, den Internetverkehr des Netzes weiterzuleiten:

```sh
juist exit serve
```

Beim ersten Mal fragt der Befehl, ob er ein Einrichtungsskript mit sudo
ausführen darf. Das Skript schaltet IP-Forwarding ein und lässt den
weitergeleiteten Verkehr durch die Firewall. Danach erscheint
`serving as an exit node`.
{{< /step >}}

{{< step on="laptop" >}}
Leite den Internetverkehr dieses Geräts über den VPS:

```sh
juist exit use vps
```

Die Ausgabe lautet `internet via vps`. `juist status` zeigt in der Zeile
`Exit node` jetzt `vps, DNS too`.
{{< /step >}}

Bist du wieder in deinem eigenen Netz, leitet `juist exit off` den Verkehr
wieder direkt ins Internet und gibt `internet direct` aus.

## Was über den Exit-Node läuft

- Verkehr zu öffentlichen Adressen im Internet geht über den Exit-Node.
- Auch DNS geht darüber, außer `juist set --dns=false` hat es abgeschaltet. Wo
  systemd-resolved läuft, werden Namen aus der eigenen Domain des LANs, etwa
  der deines Routers, weiterhin im LAN aufgelöst.
- Verkehr in dein LAN und zu den Geräten des Netzes geht weiter direkt.
- Auch Antworten auf Verbindungen aus dem Internet, etwa auf eine
  ssh-Sitzung zu diesem Gerät, gehen direkt. So bleibt das Gerät unter
  seiner eigenen Adresse erreichbar.
- Mit `juist exit use vps --isolate` gehen auch diese Antworten über den
  Exit-Node. Der Befehl bricht ab, wenn das die ssh-Sitzung beenden würde, in
  der du ihn ausführst.

## Wenn der Exit-Node nicht nutzbar ist

Kann der gewählte Exit-Node nicht genutzt werden, wird der Internetverkehr
blockiert und nicht direkt verschickt. Das passiert, wenn der Exit-Node
offline ist, seinen Dienst eingestellt oder seine Rolle verloren hat, oder
wenn der Stand des Netzes auf diesem Gerät veraltet ist. DNS-Anfragen gehen
dann ins Leere statt ins LAN. Ob du wieder direkt ins Internet gehst,
entscheidest du selbst: mit `juist exit off`.

## Hinweise

- `juist exit` listet die Exit-Nodes auf und zeigt, ob sie jeweils
  bereitstehen und welcher gerade genutzt wird.
- `juist exit use vps --force` wählt vps auch dann, wenn er noch nicht
  bereitsteht oder die Wahl deine ssh-Sitzung beenden würde.
- `juist exit serve --stop` beendet den Dienst und macht die Einrichtung
  rückgängig. Mit `juist revoke vps exit` entzieht ein Admin auf seinem Gerät
  die Rolle wieder.
- Ein Gerät, das einen Exit-Node nutzt, kann nicht selbst einer sein. Ein
  Gerät in [mehreren Netzen]({{< relref "docs/networks" >}}) leitet seinen
  Internetverkehr nur über eines davon.
- Ohne [Zugriffsregeln]({{< relref "docs/access" >}}) darf jedes Mitglied
  einen Exit-Node nutzen. Mit Zugriffsregeln nutzt ein Gerät nur die
  Exit-Nodes, die ihm eine Regel wie `pass from laptop to internet via vps`
  erlaubt, und der Exit-Node leitet nur diesen Verkehr weiter.
- Hast du die Firewall des Exit-Nodes von Hand eingerichtet, muss sie UDP und
  TCP 41646 auf `juist0` durchlassen. Dort beantwortet der Exit-Node die
  DNS-Anfragen seiner Mitglieder ([Relays, Ports und Firewalls]({{< relref "docs/relays" >}})).
- Läuft auf dem Exit-Node auch Tailscale, beantwortet er die DNS-Anfragen
  seiner Mitglieder über die normalen DNS-Server des Rechners. Den Resolver
  von Tailscale fragt er nie, denn der würde für Namen aus dem Tailnet
  Adressen liefern, die die Mitglieder nicht erreichen.
- Unter FreeBSD arbeiten Exit-Nodes mit pf, und DNS läuft über resolvconf.
- Unter Linux schaltet ein Exit-Node oder Subnet-Router auf der
  Netzwerkschnittstelle seiner Standardroute UDP-GRO-Forwarding ein, wie es
  `ethtool -K eth0 rx-udp-gro-forwarding on rx-gro-list off` tut, damit er
  UDP-Verkehr wie QUIC gebündelt weiterleitet. Beendet er den Dienst, stellt
  er die vorherigen Einstellungen der Schnittstelle wieder her. Beides steht
  im Log.
- Wird juistd ordentlich beendet, hebt er die Blockade auf. Während eines
  Neustarts des Dienstes geht der Verkehr also kurz direkt ins Internet.

## Fehlersuche

| Was du siehst | Was du tun kannst |
|---|---|
| `juist status`: `Exit node` zeigt `vps, internet refused: …` | Mach vps wieder erreichbar, oder geh mit `juist exit off` direkt ins Internet. |
| `juist exit use vps`: `vps does not serve as an exit node` | Führe auf vps `juist exit serve` aus, oder häng `--force` an. |
| `juist status`: `Exit node` zeigt `vps, internet refused: the access policy does not let this device use it` | Ergänze eine Regel `pass from … to internet via vps` ([Zugriffsregeln]({{< relref "docs/access" >}})). |
| auf vps, `juist status`: `this device does not serve: IP forwarding is off on this host` | Führe `juist exit serve` noch einmal aus, es richtet das mit sudo ein. |
| `juist health`: `warning: DNS goes to …, outside the tunnel: systemd-resolved refused juistd` | Installiere juist als Paket, dessen polkit-Regel juistd das erlaubt, und installiere polkit. |
| `juist health`: `warning: strict reverse-path filtering on … drops the exit node's answers` | Führe die Zeile `sudo sysctl -w …` aus dem Hinweis aus. |

Hinter `internet refused:` nennt der Status den Grund, etwa
`it cannot be reached`, `its operator has not agreed to serve` oder
`the network has not made it an exit node`.

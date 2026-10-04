---
title: Exit-Nodes
linkTitle: Exit-Nodes
description: Den Internetverkehr eines Geräts über ein anderes Mitglied des Netzes leiten, und ein Mitglied diesen Verkehr für die anderen übernehmen lassen.
lead: Ein Exit-Node ist ein Gerät in deinem Netz, über das die anderen ins Internet gehen. Im Café geht dein Laptop dann über deinen VPS ins Internet statt über das WLAN des Cafés.
---

## Worum es geht

Normalerweise geht ein Gerät dort ins Internet, wo es sich gerade befindet.
Mit einem Exit-Node schickt es seinen Internetverkehr zuerst durch den Tunnel
zu einem anderen Mitglied, also zu einem anderen Gerät in deinem Netz
([So funktioniert juist]({{< relref "docs/how-it-works" >}})). Dieses
Mitglied leitet den Verkehr weiter. Webseiten sehen dann die Adresse des
Exit-Nodes, und das WLAN des Cafés sieht nur verschlüsselten Verkehr.

Ein Gerät wird in zwei Schritten zum Exit-Node. Zuerst gibt ein Admin, also
eine Person, deren Schlüssel Änderungen am Netz bestätigt, dem Gerät die
Rolle `exit`. Eine Rolle ist eine Berechtigung, die das Netz für ein Gerät
festhält. Dann stimmt der Operator des Geräts zu, indem er dort
`juist exit serve` ausführt. Der [Operator]({{< relref "docs/operator" >}})
ist der lokale Benutzer, der ein Gerät ohne sudo verwaltet.

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

Die Ausgabe lautet `internet via vps`. Wo systemd-resolved läuft, zeigt
`juist status` in der Zeile `Exit node` jetzt `vps, DNS too`.
{{< /step >}}

Bist du wieder in deinem eigenen Netz, leitet `juist exit off` den Verkehr
wieder direkt ins Internet und gibt `internet direct` aus.

## Was über den Exit-Node geht und was nicht

- Verkehr zu öffentlichen Adressen im Internet geht über den Exit-Node.
- Auch DNS geht darüber, sofern auf dem Gerät systemd-resolved läuft. Namen
  aus der eigenen Domain des LANs, etwa der deines Routers, werden weiterhin
  im LAN aufgelöst.
- Verkehr in dein LAN und zu den Geräten des Netzes geht weiter direkt.
- Auch Antworten auf Verbindungen aus dem Internet, etwa auf eine
  ssh-Verbindung zu diesem Gerät, gehen direkt. So bleibt das Gerät unter
  seiner eigenen Adresse erreichbar.
- Mit `juist exit use vps --isolate` gehen auch diese Antworten über den
  Exit-Node. Der Befehl bricht ab, wenn das die ssh-Sitzung beenden würde, in
  der du ihn ausführst.

## Wenn der Exit-Node nicht nutzbar ist

Kann der gewählte Exit-Node nicht genutzt werden, wird der Internetverkehr
blockiert und nicht etwa direkt verschickt. Das passiert, wenn der Exit-Node
offline ist, seinen Dienst eingestellt oder seine Rolle verloren hat, oder
wenn der Stand des Netzes auf diesem Gerät veraltet ist. DNS-Anfragen gehen
dann ins Leere statt ins LAN. Ob du wieder direkt ins Internet gehst,
entscheidest du selbst, mit `juist exit off`.

## Gut zu wissen

- `juist exit` listet die Exit-Nodes auf, zeigt, ob sie jeweils bereitstehen,
  und welcher gerade genutzt wird.
- `juist exit use vps --force` wählt vps auch dann, wenn er noch nicht
  bereitsteht oder die Wahl deine ssh-Sitzung beenden würde.
- `juist exit serve --stop` beendet den Dienst und macht die Einrichtung
  rückgängig. Mit `juist revoke vps exit` entzieht ein Admin die Rolle.
- Ein Gerät, das einen Exit-Node nutzt, kann nicht selbst einer sein. Ein
  Gerät in [mehreren Netzen]({{< relref "docs/networks" >}}) leitet seinen
  Internetverkehr nur über eines davon.
- Ein Exit-Node steht jedem Mitglied offen. Es gibt keine Zugriffsregeln
  (ACLs), die festlegen, wer ihn nutzen darf.
- Eine von Hand eingerichtete Firewall auf dem Exit-Node muss UDP und TCP
  41646 auf `juist0` durchlassen, denn dort beantwortet er die DNS-Anfragen
  seiner Mitglieder ([Relays, Ports und Firewalls]({{< relref "docs/relays" >}})).
- Unter FreeBSD arbeiten Exit-Nodes mit pf, und DNS läuft über resolvconf.
- Wird juistd ordentlich beendet, hebt er die Blockade auf. Während eines
  Neustarts des Dienstes geht der Verkehr also kurz direkt ins Internet.

## Wenn etwas nicht klappt

| Was du siehst | Was du tun kannst |
|---|---|
| `juist status`: `Exit node` zeigt `vps, internet refused: …` | Mach vps wieder erreichbar, oder geh mit `juist exit off` direkt ins Internet. |
| `juist exit use vps`: `vps does not serve as an exit node` | Führe auf vps `juist exit serve` aus, oder häng `--force` an. |
| auf vps, `juist status`: `this device does not serve: IP forwarding is off on this host` | Führe `juist exit serve` noch einmal aus, es richtet das mit sudo ein. |
| `warning: DNS goes to …, outside the tunnel: systemd-resolved refused juistd` | Installiere das Paket, dessen polkit-Regel juistd das erlaubt, und polkit. |
| `warning: strict reverse-path filtering on … drops the exit node's answers` | Führe die Zeile `sudo sysctl -w …` aus, die der Hinweis ausgibt. |

Hinter `internet refused:` nennt der Status den Grund, etwa
`it cannot be reached`, `its operator has not agreed to serve` oder
`the network has not made it an exit node`.

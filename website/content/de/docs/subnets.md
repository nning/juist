---
title: Subnet-Router
linkTitle: Subnet-Router
description: Das LAN hinter einem Mitglied, etwa den Drucker zu Hause, von jedem Gerät des Netzes aus erreichen.
lead: Ein Subnet-Router ist ein Mitglied, das Verkehr aus dem Netz in sein LAN weiterleitet. Dein Laptop erreicht dann den Drucker zu Hause von überall, obwohl auf dem Drucker kein juist läuft.
---

## So funktioniert es

Dein NAS zu Hause ist ein Mitglied, also ein Gerät, das zu deinem Netz gehört
([So funktioniert juist]({{< relref "docs/how-it-works" >}})). Der Drucker
daneben ist keines, denn auf ihm läuft kein juist. Mit einem Subnet-Router sind
solche Geräte trotzdem für andere Mitglieder erreichbar: Das NAS nimmt den
Verkehr für sie aus dem Tunnel und leitet ihn in sein LAN weiter, in diesem
Beispiel `192.168.1.0/24`. Einen solchen Adressbereich nennt man Subnetz.

Ein Gerät wird in zwei Schritten zum Subnet-Router. Zuerst weist ein Admin,
also eine Person, deren Schlüssel Änderungen am Netz bestätigt, dem Gerät das
Subnetz zu. Dann stimmt der [Operator]({{< relref "docs/operator" >}}) des Geräts zu, also
der lokale Benutzer, der es ohne sudo verwaltet, indem er dort
`juist subnet serve` ausführt.

Für die Geräte im LAN kommen die Verbindungen vom NAS. Sie brauchen also
keine eigene Einrichtung.

## Einen Subnet-Router einrichten

{{< step on="dem Gerät eines Admins" >}}
Lass nas sein LAN für das Netz routen:

```sh
juist subnet add nas 192.168.1.0/24
```

Braucht eine Änderung mehr als einen Admin, wartet sie auf die anderen
([wie Änderungen bestätigt werden]({{< relref "docs/network-changes" >}})).
{{< /step >}}

{{< step on="nas" as="dem Subnet-Router" >}}
Stimm zu, die Subnetze zu routen, die das Netz diesem Gerät zuweist:

```sh
juist subnet serve
```

Beim ersten Mal fragt der Befehl, ob er ein Einrichtungsskript mit sudo
ausführen darf. Das Skript schaltet IP-Forwarding ein und lässt den Verkehr
durch die Firewall. Danach erscheint `routing 192.168.1.0/24`.
{{< /step >}}

{{< step on="laptop" >}}
Hier musst du nichts tun. Jedes Mitglied übernimmt die Route von selbst, und
`juist subnet` zeigt sie an:

```console
$ juist subnet
PREFIX          ROUTER  STATE
192.168.1.0/24  nas     in use
```
{{< /step >}}

## Dein eigenes LAN hat Vorrang

Hat ein Mitglied schon eine eigene Route zu diesen Adressen, nutzt es weiter
diese. Ist dein Laptop zu Hause selbst im `192.168.1.0/24`, spricht
er direkt mit dem Drucker und nicht über das NAS. `juist subnet` meldet dann
`this device reaches it by a route of its own`.

## Hinweise

- `juist subnet` listet alle Subnetze mit ihrem Router auf und zeigt ihren
  Zustand auf diesem Gerät. `juist status` fasst das in der Zeile `Subnets`
  zusammen.
- Mit `juist subnet remove nas 192.168.1.0/24` entfernt ein Admin das
  Subnetz auf seinem Gerät wieder.
- `juist subnet serve --stop` beendet das Routen auf dem Router und macht die
  Einrichtung rückgängig.
- Nach `juist subnet off` erreicht ein Gerät keines der Subnetze mehr über das
  Netz, und der Rechner routet diese Adressen wieder wie zuvor. `juist subnet on`
  macht das rückgängig.
- Zwei Mitglieder können keine überlappenden Subnetze routen, und ein
  Subnetz darf sich nicht mit den Adressen des Netzes selbst überschneiden.
  Für das ganze Internet (`0.0.0.0/0`) nimmst du einen
  [Exit-Node]({{< relref "docs/exit-nodes" >}}).
- Ohne [Zugriffsregeln]({{< relref "docs/access" >}}) erreicht jedes
  Mitglied ein geroutetes Subnetz. Mit Zugriffsregeln erreicht ein Gerät
  nur die Adressen, die ihm eine Regel wie `pass from laptop to 192.168.1.0/24`
  erlaubt, und der Router leitet nur diesen Verkehr weiter.
- Nutzt ein Gerät einen Exit-Node, läuft der Verkehr zu einem gerouteten
  Subnetz trotzdem über dessen Router.
- Subnet-Router gibt es unter Linux und unter FreeBSD mit pf.
- Docker verwirft gerouteten Verkehr zu seinen Containern.
  `juist subnet serve` warnt, wenn ein Subnetz ein Docker-Netz enthält.
- Hosts im Subnetz erreichen die Mitglieder, aber nicht die juist-Adresse des
  Routers selbst: Unter Linux antwortet der Router unter dieser Adresse nur
  durch den Tunnel.

## Fehlersuche

Auf einem Gerät, das ein Subnetz nicht erreicht, nennt `juist subnet` den Grund
hinter `not in use:`:

| Grund | Was du tun kannst |
|---|---|
| `its router cannot be reached` | Bring den Router wieder online. |
| `its router's operator has not agreed to route it` | Führe auf dem Router `juist subnet serve` aus. |
| `subnets are off on this device` | Führe `juist subnet on` aus. |
| `the access policy passes none of it to this device` | Ergänze eine Regel für das Subnetz ([Zugriffsregeln]({{< relref "docs/access" >}})). |
| `this device's view of the network is stale` | Bring einen Voucher wieder online, also ein Gerät, das den aktuellen Stand des Netzes bestätigt. Siehe [Status]({{< relref "docs/status" >}}). |

Auf dem Router selbst bedeutet `not routed: not agreed to on this device`,
dass dort `juist subnet serve` noch nicht ausgeführt wurde. Solange dem Gerät
kein Subnetz zugewiesen ist, meldet `juist subnet serve`
`will route once an admin grants this device a subnet`.

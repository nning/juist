---
title: Subnet-Router
linkTitle: Subnet-Router
description: Das LAN hinter einem Mitglied, etwa den Drucker zu Hause, von jedem Gerät des Netzes aus erreichen.
lead: Ein Subnet-Router ist ein Mitglied, das Verkehr aus dem Netz in sein LAN weiterleitet. Dein Laptop erreicht dann den Drucker zu Hause von überall, obwohl auf dem Drucker kein juist läuft.
---

## Worum es geht

Dein NAS zu Hause ist ein Mitglied, also ein Gerät, das zu deinem Netz gehört
([So funktioniert juist]({{< relref "docs/how-it-works" >}})). Der Drucker
daneben ist keines, auf ihm läuft kein juist. Mit einem Subnet-Router sind
solche Geräte trotzdem für jedes Mitglied erreichbar: Das NAS nimmt den
Verkehr für sie aus dem Tunnel und leitet ihn in sein LAN weiter, in diesem
Beispiel `192.168.1.0/24`. Einen solchen Adressbereich nennt man Subnetz.

Ein Gerät wird in zwei Schritten zum Subnet-Router. Zuerst weist ein Admin,
also eine Person, deren Schlüssel Änderungen am Netz bestätigt, dem Gerät das
Subnetz zu. Dann stimmt der Operator des Geräts zu, indem er dort
`juist subnet serve` ausführt. Der [Operator]({{< relref "docs/operator" >}})
ist der lokale Benutzer, der ein Gerät ohne sudo verwaltet.

Für die Geräte im LAN kommen die Verbindungen vom NAS. Sie müssen also nicht
eigens eingerichtet werden.

## Einen Subnet-Router einrichten

{{< step on="dem Gerät eines Admins" >}}
Lass nas sein LAN für alle Mitglieder routen:

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

Erreicht ein Mitglied diese Adressen schon über eine eigene Route, nutzt es
weiterhin diese. Ist dein Laptop zu Hause selbst im `192.168.1.0/24`, spricht
er direkt mit dem Drucker und nicht über das NAS. `juist subnet` meldet dann
`this device reaches it by a route of its own`.

## Gut zu wissen

- `juist subnet` listet alle Subnetze mit ihrem Router auf und zeigt, wie
  dieses Gerät sie nutzt. `juist status` fasst das in der Zeile `Subnets`
  zusammen.
- Mit `juist subnet remove nas 192.168.1.0/24` nimmt ein Admin das Subnetz
  wieder weg.
- `juist subnet serve --stop` beendet das Routen auf dem Router und macht die
  Einrichtung rückgängig.
- Nach `juist subnet off` erreicht ein Gerät keines der Subnetze mehr über das
  Netz, der Rechner routet sie wieder selbst wie zuvor. `juist subnet on`
  macht das rückgängig.
- Zwei Mitglieder können keine überlappenden Subnetze routen, und ein
  Subnetz darf sich nicht mit den Adressen des Netzes selbst überschneiden.
  Für das ganze Internet (`0.0.0.0/0`) nimmst du einen
  [Exit-Node]({{< relref "docs/exit-nodes" >}}).
- Jedes Mitglied erreicht ein geroutetes Subnetz. Es gibt keine
  Zugriffsregeln (ACLs), die das einschränken.
- Auch wenn ein Exit-Node genutzt wird, läuft ein geroutetes Subnetz weiter
  über seinen Router.
- Subnet-Router gibt es unter Linux und unter FreeBSD mit pf.
- Docker verwirft gerouteten Verkehr zu seinen Containern.
  `juist subnet serve` warnt, wenn ein Subnetz ein Docker-Netz enthält.

## Wenn etwas nicht klappt

Auf dem Gerät, das ein Subnetz nicht erreicht, nennt `juist subnet` den Grund
hinter `not in use:`:

| Meldung | Was du tun kannst |
|---|---|
| `its router cannot be reached` | Bring den Router wieder online. |
| `its router's operator has not agreed to route it` | Führe auf dem Router `juist subnet serve` aus. |
| `subnets are off on this device` | Führe `juist subnet on` aus. |
| `this device's view of the network is stale` | Bring einen Voucher wieder online, also ein Gerät, das den aktuellen Stand des Netzes bestätigt. Siehe [Status]({{< relref "docs/status" >}}). |

Auf dem Router selbst bedeutet `not routed: not agreed to on this device`,
dass dort `juist subnet serve` noch nicht ausgeführt wurde. Solange dem Gerät
kein Subnetz zugewiesen ist, meldet `juist subnet serve`
`will route once an admin grants this device a subnet`.

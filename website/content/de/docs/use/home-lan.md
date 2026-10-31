---
title: Das Heimnetz von unterwegs
linkTitle: Das Heimnetz von unterwegs
description: Drucker, Weboberfläche des Routers oder Kameras zu Hause von überall erreichen, obwohl auf ihnen kein juist läuft, über ein Mitglied im Heimnetz.
lead: Auf Drucker, Router und Kameras zu Hause wird nie juist laufen. Ein Mitglied im Heimnetz, etwa das NAS, reicht den Verkehr des Netzes an sie weiter, und dein Laptop erreicht sie von überall unter ihren gewohnten Adressen.
---

## Was du bekommst

Dein Laptop öffnet `192.168.1.1` für die Weboberfläche des Routers, druckt
auf `192.168.1.20` und zeigt das Bild einer Kamera, als wäre er zu Hause.
Das NAS ist ein [Subnet-Router]({{< relref "docs/subnets" >}}): Es nimmt
diesen Verkehr aus dem Tunnel und gibt ihn in sein LAN weiter. Die Geräte im
LAN sehen Verbindungen vom NAS und müssen nicht eingerichtet werden.

Im Beispiel ist das LAN `192.168.1.0/24`, und das NAS heißt `nas`.

## Was du brauchst

- Ein Netz, in dem der Laptop ist ([das erste Netz]({{< relref "docs/first-network" >}})).
- Ein Mitglied zu Hause unter Linux oder unter FreeBSD mit pf, das
  eingeschaltet bleibt: ein NAS, ein kleiner Server oder ein Raspberry Pi.
- Laptops unter Linux oder FreeBSD. Die Android-App kann keinen
  Subnet-Router nutzen.

## Einrichten

{{< step on="nas" as="dem Mitglied zu Hause" >}}
[Installiere juist]({{< relref "docs/install" >}}) und tritt dem Netz mit
einer [Einladung]({{< relref "docs/invites" >}}) bei.
{{< /step >}}

{{< step on="dem Gerät eines Admins" >}}
Lass nas sein LAN für das Netz routen:

```sh
juist subnet add nas 192.168.1.0/24
```

Das ist eine Änderung am Netz, die die Admins bestätigen.
{{< /step >}}

{{< step on="nas" >}}
Stimme dem Routen zu:

```sh
juist subnet serve
```

Beim ersten Mal fragt es, ob es ein Einrichtungsskript mit sudo ausführen
darf. Danach lautet die Ausgabe `routing 192.168.1.0/24`.
{{< /step >}}

{{< step on="laptop" >}}
Hier ist nichts einzurichten. `juist subnet` zeigt das Subnetz als `in use`.
{{< /step >}}

## Darauf achten

- **Ein LAN mit denselben Adressen hat Vorrang.** In einem Hotel, dessen Netz
  ebenfalls `192.168.1.0/24` ist, erreicht der Laptop die Geräte des Hotels,
  nicht deine. Ein seltenerer Bereich zu Hause, etwa `192.168.73.0/24`,
  vermeidet das.
- **Jedes Mitglied erreicht das ganze LAN.** Ohne
  [Zugriffsregeln]({{< relref "docs/access" >}}) gilt das auch für die
  Weboberfläche des Routers und jede Kamera. Eine Regel wie
  `pass from laptop to 192.168.1.20` lässt ein Gerät nur zu dem durch, was
  es braucht.
- **Docker verwirft gerouteten Verkehr zu seinen Containern.**
  `juist subnet serve` warnt, wenn das Subnetz ein Docker-Netz enthält.

## Weiterlesen

- [Subnet-Router]({{< relref "docs/subnets" >}}): jeder Zustand und Grund,
  den `juist subnet` anzeigt
- [Zugriffsregeln]({{< relref "docs/access" >}})
- [Exit-Nodes]({{< relref "docs/exit-nodes" >}}), für das ganze Internet
  statt eines LANs

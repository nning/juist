---
title: Geräte im ganzen Netz finden
linkTitle: Multicast
description: Programme, die sich im LAN per Multicast finden, etwa Drucker, Medienserver und LAN-Spiele, finden so auch die Mitglieder deines Netzes.
lead: Viele Programme finden sich per Multicast. AirPlay und Drucker nutzen mDNS, Medienserver SSDP, Windows WS-Discovery und LAN-Spiele eigene Gruppen. juist überträgt dieses Multicast zwischen den Mitgliedern, als teilten sie ein LAN.
---

## So funktioniert es

Ein Programm, das Multicast auf `juist0` sendet, erreicht die Programme auf
den anderen Mitgliedern, die auf ihrem `juist0` lauschen. juist überträgt UDP
an Multicast-Gruppen, über IPv4 und IPv6. Das Datagramm kommt mit der Adresse
des Absenders im Netz an, also geht eine Antwort direkt an ihn zurück.

Auch Pings an IPv6-Gruppen überträgt es, sodass `ping -I juist0 ff02::1`
die Mitglieder zeigt, die antworten, jedes mit seiner Link-local-Adresse.

Ohne Zugriffsregeln sind Multicast und Discovery-Kopien von Haus aus an.
Mit Zugriffsregeln sind sie aus, bis eine passende Regel `pass multicast`
sie erlaubt, nach Gerät, Richtung und Port. `sudo juist set --multicast=false`
schaltet beides auch bei erlaubender Policy aus. Jedes erlaubte Mitglied kann auf den anderen
Suchanfragen beantworten, wie ein Gerät in deinem LAN. Es kann einen Drucker
oder einen Medienserver ankündigen, und die Antwort enthält seine Adresse im
Netz.

juist überträgt nicht:

- Multicast von anderen Geräten in deinem LAN. Nur was ein Mitglied selbst
  sendet, geht hinüber.
- DHCP-Broadcasts (UDP-Quell- oder Zielports 67 und 68) sowie fragmentierte Broadcasts.
- IPv6-Gruppen außer denen mit Link-Scope (`ff02::`) und Site-Scope
  (`ff05::`).
- ICMP an eine Gruppe außer einem IPv6-Ping, etwa Router Advertisements,
  Neighbor Discovery oder MLD.
- DHCPv6, damit kein Mitglied den anderen Adressen oder DNS-Server zuteilt.
- Multicast unter [Zugriffsregeln]({{< relref "docs/access" >}}), außer eine
  Regel `pass multicast` lässt es durch.

Ein Mitglied sendet höchstens 100 Datagramme pro Sekunde, in Schüben bis
200. Was darüber hinausgeht, verwerfen die anderen.

## Unter Zugriffsregeln

Mit [Zugriffsregeln]({{< relref "docs/access" >}}) geht Multicast nur dort
durch, wo eine Regel es erlaubt, von Gerät zu Gerät:

```text
pass multicast from <familie> to <familie>
pass multicast from <spieler> to <spieler> port 4445
```

Die erste Regel, ohne Port, lässt auch Pings durch. Die zweite lässt nur
UDP-Port 4445 durch, die eigene Gruppe eines Spiels. Jede Regel lässt auch die Antworten durch, die ein Gerät direkt
zurückschickt. Solche Regeln brauchen Schema 22 des Netzes, siehe
[Aktualisieren]({{< relref "docs/updating" >}}).

## Programme auf dem Standard-Interface

Unter Linux kopiert juist die eigenen IPv4-UDP-Multicasts automatisch
zusätzlich zum LAN ins Netz. Programme, die nur das Standard-Interface
nutzen, etwa Minecraft Java, brauchen keine Gruppenkonfiguration.
`juist status` zeigt:

```console
  Multicast     on, copied: auto
```

Das Kopieren folgt diesen Berechtigungen auf jedem beteiligten Linux-Mitglied.
Vorhandene ausdrückliche Gruppenlisten bleiben erhalten. So stellst du den
automatischen Standard wieder her:

```sh
sudo juist set --groups auto
```

Für nur bestimmte Gruppen gibst du eine Liste mit Kommas an, etwa
`sudo juist set --groups 239.255.255.250` für SSDP. `sudo juist set --groups ""`
beendet das Kopieren von Gruppen und gibt `groups off` aus; Broadcast bleibt an.

Das Original geht weiterhin ins LAN. Das Kopieren funktioniert nur unter
Linux mit IPv4, für unfragmentierte UDP-Pakete bis 1280 Byte einschließlich
IP-Header (1252 Byte Nutzdaten). Eine Änderung der Gruppen startet die
Tunnel des Geräts neu, was ein paar Sekunden dauert. IPv6-Programme müssen
selbst auf `juist0` senden und lauschen.

### Minecraft Java Edition

Mit dem automatischen Standard ist unter Linux keine Gruppenkonfiguration nötig.
Unter Zugriffsregeln sind die folgenden Discovery- und Spielberechtigungen weiterhin nötig.

Java Edition kündigt eine geöffnete LAN-Welt auf UDP-Port 4445 an. Die Kopie
trägt die juist-Adresse des Hosts, sodass der Client sich über juist
verbindet; Spieler im ursprünglichen LAN empfangen die Ankündigung weiterhin.
Unter Zugriffsregeln erlaubst du Multicast auf Port 4445 und den TCP-Port
des Spiels getrennt. Der TCP-Port ist der beim Öffnen der Welt gewählte.

Javas Multicast-Socket tritt der Gruppe nur auf dem Standard-Interface bei.
Bei automatischem Kopieren oder einer passenden ausdrücklichen Gruppenliste
stellt juist deshalb zusätzlich eine lokale
UDP-Unicast-Kopie mit unverändertem Absender zu. Unter Zugriffsregeln braucht
diese Kopie zusätzlich gewöhnlichen UDP-Zugriff auf Port 4445. Zum Beispiel,
wenn du im LAN-Dialog TCP-Port 25565 wählst:

```text
pass multicast from <spieler> to <spieler> port 4445
pass from <spieler> to <spieler> proto udp port 4445
pass from <spieler> to <spieler> proto tcp port 25565
```

Das ursprüngliche Multicast erreicht weiterhin die Empfänger auf `juist0`.
Ein Programm, das beide Zustellungen annimmt, kann zwei Kopien sehen.
Inhalt und Absender bleiben unverändert. Ein Socket, der nur an eine
LAN-Adresse, ein LAN-Interface oder eine Gruppenadresse gebunden ist, kann
weiterhin eigene Unterstützung für `juist0` brauchen.

## Was andere Mitglieder erfahren

Das automatische Kopieren umfasst Discovery von jedem Programm auf diesem
Host, auch wenn du es nicht bewusst über juist nutzt. Dadurch können
Gerätenamen, Dienstkennungen und andere normalerweise fürs LAN bestimmte
Informationen die Mitglieder erreichen. Ohne Policy kann jedes Mitglied sie
empfangen. Begrenze die Empfänger mit Zugriffsregeln oder schalte es hier
mit `sudo juist set --multicast=false` ab.

## UDP-Broadcast

Unter Linux kopiert juist die eigenen IPv4-UDP-Broadcasts automatisch ins
Netz, solange Multicast an ist. Es kopiert `255.255.255.255` und Subnetz-
Broadcasts; letztere kommen als `255.255.255.255` an. Die Originale gehen
weiterhin ins LAN. Eine Portliste ist nicht nötig. Das Paket muss mit
IP-Header in 1280 Byte passen und darf nicht fragmentiert sein. DHCP-
Broadcasts bleiben ausgenommen. NetBIOS auf UDP-Port 137 und 138 nutzt
denselben Broadcast-Pfad, ohne eigene Behandlung von Adressen oder Namen.

Für Broadcast gelten dieselben `pass multicast`-Regeln und Mengenlimits wie
für Multicast. Eine Antwort auf den UDP-Quellport ist zehn Sekunden lang
erlaubt. Ein Programm, das nur an seine LAN-Adresse oder sein LAN-Interface
gebunden ist, empfängt Pakete auf `juist0` möglicherweise nicht. Adressen
im Inhalt einer Suchnachricht werden nicht übersetzt.

Das automatische Kopieren funktioniert nur unter Linux. Unter FreeBSD
müssen Multicast-Programme selbst auf `juist0` senden und lauschen. Die
Android-App überträgt weder Multicast noch Broadcast.

## Avahi

Unter Linux und FreeBSD fragt und antwortet avahi für viele Programme per mDNS. Es lässt
ein Gerät wie `juist0` aus, solange seine Konfiguration es nicht erlaubt.
`juist health` warnt davor:

```console
warning: avahi leaves juist0 out, a point-to-point device: members are not found by mDNS
hint: set allow-point-to-point=yes under [server] in /etc/avahi/avahi-daemon.conf, then restart avahi-daemon
```

Füge die Zeile unter `[server]` in `/etc/avahi/avahi-daemon.conf` ein, unter
FreeBSD in `/usr/local/etc/avahi/avahi-daemon.conf`:

```ini
[server]
allow-point-to-point=yes
```

Starte avahi danach neu, unter FreeBSD mit `service avahi-daemon restart`:

```sh
sudo systemctl restart avahi-daemon
```

## Abschalten

```sh
sudo juist set --multicast=false
```

Das schaltet Multicast und Broadcast auch bei erlaubender Policy ab. Es gibt `multicast off` aus, und `juist status` zeigt `Multicast off`.
`sudo juist set --multicast` erlaubt Discovery wieder dort, wo die Policy es zulässt. Beides startet die
Tunnel des Geräts neu, was ein paar Sekunden dauert.

Die Android-App überträgt kein Multicast.

## Wenn etwas nicht klappt

- **Ein Programm findet kein Mitglied.** Führe `juist health` aus und achte
  auf die Warnung zu avahi. Prüfe unter Linux, ob `juist status`
  `copied: auto` oder die Gruppe des Programms zeigt. Auf anderen Systemen
  muss das Programm auf `juist0` lauschen.
- **`juist status` zeigt keine Zeile `Multicast`.** Das Gerät hat kein
  `juist0`, wie ein [Service-Mitglied]({{< relref "docs/service-member" >}}).

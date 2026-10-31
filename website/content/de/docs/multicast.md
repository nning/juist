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

Multicast ist von Haus aus an. Jedes Mitglied kann dann auf den anderen
Suchanfragen beantworten, wie ein Gerät in deinem LAN. Es kann einen Drucker
oder einen Medienserver ankündigen, und die Antwort enthält seine Adresse im
Netz.

juist überträgt nicht:

- Multicast von anderen Geräten in deinem LAN. Nur was ein Mitglied selbst
  sendet, geht hinüber.
- Broadcast, etwa an `255.255.255.255`.
- IPv6-Gruppen außer denen mit Link-Scope (`ff02::`) und Site-Scope
  (`ff05::`).
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

Die zweite Regel lässt nur UDP-Port 4445 durch, die eigene Gruppe eines
Spiels. Jede Regel lässt auch die Antworten durch, die ein Gerät direkt
zurückschickt. Solche Regeln brauchen Schema 22 des Netzes, siehe
[Aktualisieren]({{< relref "docs/updating" >}}).

## Programme auf dem Standard-Interface

Viele Programme lauschen und senden auf jedem Interface, auch auf `juist0`. Manche nutzen nur das Standard-Interface des Hosts, meist das des
LANs. Für sie leitest du ihre Gruppe ins Netz.

{{< step on="laptop" >}}
Leite die Gruppe von SSDP ins Netz:

```sh
sudo juist set --groups 239.255.255.250
```

Es gibt `groups 239.255.255.250` aus, und `juist status` zeigt:

```console
  Multicast     on, routed: 239.255.255.250
```
{{< /step >}}

{{< step on="nas" as="den anderen Mitgliedern" >}}
Mach dasselbe auf jedem Mitglied, auf dem ein solches Programm läuft, damit
es die Gruppe ebenfalls auf seinem Standard-Interface empfängt.
{{< /step >}}

Eine geleitete Gruppe geht von diesem Gerät an die Mitglieder und nicht mehr
ins LAN. Mehrere Gruppen trennst du mit Kommas. `sudo juist set --groups ""`
leitet wieder keine. Gruppen leitest du nur unter Linux ins Netz, und nur
IPv4. Eine Änderung der Gruppen startet die Tunnel des Geräts neu, was ein
paar Sekunden dauert.

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

Es gibt `multicast off` aus, und `juist status` zeigt `Multicast off`.
`sudo juist set --multicast` schaltet es wieder an. Beides startet die
Tunnel des Geräts neu, was ein paar Sekunden dauert.

Die Android-App überträgt kein Multicast.

## Wenn etwas nicht klappt

- **Ein Programm findet kein Mitglied.** Führe `juist health` aus und achte
  auf die Warnung zu avahi. Prüfe, ob das Programm auf `juist0` lauscht,
  oder leite seine Gruppe wie oben ins Netz.
- **`juist status` zeigt keine Zeile `Multicast`.** Das Gerät hat kein
  `juist0`, wie ein [Service-Mitglied]({{< relref "docs/service-member" >}}).

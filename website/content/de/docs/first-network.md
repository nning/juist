---
title: Das erste Netz
linkTitle: Das erste Netz
description: Ein Netz auf einem Gerät anlegen, ein zweites einladen und prüfen, ob sich beide erreichen.
lead: Zwei Geräte, ein Netz, ein paar Minuten. Du legst das Netz auf dem einen Gerät an, lädst das andere ein, vergleichst vier Wörter und schickst einen Ping.
---

## Worum es geht

Angenommen, du hast zu Hause einen Laptop und ein NAS, und auf beiden ist
juist [installiert]({{< relref "docs/install" >}}). Der Laptop wird das erste
Gerät in einem Netz namens `home`, danach lädst du das NAS ein.

Ein **Netz** besteht aus den Geräten, die sich über juist erreichen, und jedes
davon ist ein **Mitglied**. Wer das Netz anlegt, wird sein erster **Admin**,
also der Mensch, dessen Schlüssel Änderungen wie das Aufnehmen eines Geräts
signiert. Mehr dazu unter [So funktioniert juist]({{< relref "docs/how-it-works" >}}).

## Das Netz anlegen und ein Gerät einladen

{{< step on="laptop" as="das erste Gerät" >}}
Leg das Netz als du selbst an, ohne sudo. Dein Admin-Schlüssel gehört in
deinen eigenen Keystore, also ins Verzeichnis `~/.config/juist` in deinem
Home-Verzeichnis.

```console
$ juist create home
not the operator; run sudo juist set --operator=alice? [Y/n] y
operator alice
created network "home"
  This device   laptop  198.18.36.1  fd84:7a1f:97ee:5630:7c56:12b6:971f:2222
  IPv4 range    198.18.36.0/22
  Quorum        1 of 1 vote
  Admin         alice
  Break-glass   /home/alice/.config/juist/break-glass-home.secrets (keep offline)
  Operator      alice
```

juist fragt einmal nach sudo, um dich zum **Operator** des Geräts zu machen.
Das ist der lokale Benutzer, der das Gerät ab dann ohne sudo verwaltet. Gibst
du keinen Namen an, benennt `juist create` das Netz mit zwei zufälligen
Wörtern.
{{< /step >}}
{{< step on="laptop" >}}
Lade das neue Gerät ein:

```console
$ juist invite
invite to "home", expires in 1h; on the new device:

  juist join 42-drumbeat-tolerance-glucose  # same LAN

  juist join 'juist:Kx7…@192.168.1.20:41642'
```

Du bekommst einen Code für ein Gerät im selben LAN und einen Link für ein
Gerät, das woanders steht. Danach wartet die Einladung.
{{< /step >}}
{{< step on="nas" as="das neue Gerät" >}}
Tritt mit dem Code bei, oder mit dem Link, falls das NAS woanders steht:

```console
$ sudo juist join 42-drumbeat-tolerance-glucose
looking for the inviting device on the LAN
connected to 192.168.1.20:41642
tell the inviting admin these words:
  atlas-amulet-banjo-asteroid
```

Mit sudo wird der Benutzer, der sudo aufgerufen hat, Operator des NAS.
{{< /step >}}
{{< step on="laptop" >}}
Auch die Einladung zeigt nun vier Wörter. Antworte nur mit `y`, wenn es
dieselben sind wie auf dem NAS:

```console
nas wants to join; compare with the words it shows:
  atlas-amulet-banjo-asteroid
same? [y/N] y
admitting nas (nid:fcRW83T_…)
admitted nas at 198.18.36.2
nas joined
```

Auf dem NAS endet `juist join` mit den Adressen des Geräts:

```console {device="nas"}
joined "home" as nas
  Addresses     198.18.36.2  fd84:7a1f:97ee:21a8:2ab0:e8e:caa0:b306
  Devices       2
  Operator      alice
```
{{< /step >}}
{{< step on="einem der beiden Geräte" >}}
Prüfe, ob sich beide erreichen:

```console
$ juist status
home · connected
  This device   laptop  198.18.36.1  fd84:7a1f:97ee:5630:7c56:12b6:971f:2222
  Devices       1 other, heard from
  Tunnels       1 of 1 live
  Names         home.juist
  Freshness     vouched just now, valid 48h
  Ports         udp/41643
  Updated       just now

NAME                  IPV4         IPV6                                     ROLES    REACHED
laptop (this device)  198.18.36.1  fd84:7a1f:97ee:5630:7c56:12b6:971f:2222  voucher  -
nas                   198.18.36.2  fd84:7a1f:97ee:21a8:2ab0:e8e:caa0:b306   -        direct
$ ping 198.18.36.2
```

`juist devices` gibt nur die Geräteliste aus. Wo systemd-resolved läuft,
klappt auch `ping nas.home.juist`.
{{< /step >}}

## Hinter NAT oder mit öffentlicher Adresse

Der Link funktioniert auch, wenn beide Geräte an verschiedenen Orten hinter
NAT stehen, etwa der Laptop bei dir zu Hause und das NAS bei einem Freund. Sie
finden sich dann über den öffentlichen BitTorrent-DHT, was etwa eine Minute
dauert. Das scheitert nur, wenn beide NATs symmetrisch sind. Dann trittst du
über einen Internetanschluss bei, von dem aus das einladende Gerät erreichbar
ist, oder richtest vorher ein [Relay]({{< relref "docs/relays" >}}) ein. Die
Einzelheiten stehen unter
[Geräte einladen]({{< relref "docs/invites" >}}).

Hinter NAT musst du keine Firewall-Ports öffnen. Ein Gerät mit öffentlicher
Adresse, etwa ein VPS, braucht 41643/udp.

## Gut zu wissen

- `juist create home` nennt das Netz `home`. Das Gerät bekommt den
  Rechnernamen, es sei denn, du gibst `--device` an.
- Der IPv4-Bereich ist ein zufälliges `/22` aus `198.18.0.0/15`, etwa
  `198.18.36.0/22`. Mit `--ipv4` legst du ihn selbst fest.
- Der Code funktioniert nur im selben LAN, und schon ein falscher Versuch
  macht ihn ungültig. Der Link bleibt dann trotzdem gültig.
- Eine Einladung gilt eine Stunde und für genau ein Gerät. Für das nächste
  rufst du `juist invite` erneut auf.
- Die Break-glass-Datei liest kein juist-Befehl. Bewahre sie trotzdem
  offline auf.
- Der Laptop ist der erste **Voucher** des Netzes, also ein Gerät, das
  stündlich bestätigt, dass der Stand des Netzes aktuell ist. Halte immer
  einen Voucher online. Mehr dazu unter [Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers).

## Wenn etwas nicht klappt

| Was du siehst | Was du tun kannst |
|---|---|
| `juist: run as alice, without sudo: the admin key belongs in your keystore` | Ruf `juist create` ohne sudo auf. |
| `juistd not running` in `juist status` | `sudo systemctl enable --now juistd` |
| `read-only; to manage this device …` | einmal `sudo juist set --operator=$USER` |
| `warning: code voided: wrong guess from …` | Tritt mit dem Link bei, der weiterhin gilt. Kam der Fehlversuch nicht von deinem Gerät, kennt jemand anderes die Einladung. |
| `juist: words not confirmed; nothing signed` | Wichen die Wörter voneinander ab, ist das anfragende Gerät nicht das eingeladene. Starte eine neue Einladung. |
| `no answer from a device` in `juist status` | Das Gerät ist offline, oder sein Port 41643/udp ist gesperrt. |
| `no tunnel traffic from a device` | Öffne 41643/udp auf einem Gerät mit öffentlicher Adresse, oder gib einem Gerät die Rolle `relay`. |

Weitere Fälle stehen unter [Fehlersuche]({{< relref "docs/troubleshooting" >}}).

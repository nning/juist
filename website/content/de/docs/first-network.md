---
title: Das erste Netz
linkTitle: Das erste Netz
description: Ein Netz auf einem Gerät anlegen, ein zweites einladen und prüfen, ob sich beide erreichen.
lead: Zwei Geräte, ein Netz, ein paar Minuten. Du legst das Netz auf dem einen Gerät an, lädst das andere ein, vergleichst vier Wörter und schickst einen Ping.
---

## Was du einrichtest

Angenommen, du hast zu Hause einen Laptop und ein NAS, und auf beiden ist
juist [installiert]({{< relref "docs/install" >}}). Der Laptop wird das erste
Gerät in einem Netz namens `home`, danach lädst du das NAS ein.

Ein **Netz** besteht aus den Geräten, die sich über juist erreichen, und jedes
davon ist ein **Mitglied**. Wer das Netz anlegt, wird sein erster **Admin**,
also der Mensch, dessen Schlüssel Änderungen wie das Aufnehmen eines Geräts
signiert. Mehr dazu unter [So funktioniert juist]({{< relref "docs/how-it-works" >}}).

## Das Netz anlegen und ein Gerät einladen

{{< step on="laptop" as="das erste Gerät" >}}
Leg das Netz mit deinem eigenen Benutzer an, ohne sudo. Dein Admin-Schlüssel gehört in
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
  Break-glass   juist-break-glass-1.qL0x…dW8.u3Rk6g
  Operator      alice
warning: the break-glass secret is shown only now and kept nowhere: keep it safe, apart from the admin keys
hint: with it, juist network disable ends the network once too few admin keys are left to change it
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

  juist join 'juist:Kx7…@192.168.1.20:41642'

  juist join 42-drumbeat-tolerance-glucose  # same LAN
```

Du bekommst einen Link, der für ein Gerät an jedem Ort funktioniert, darüber
denselben Link als QR-Code (hier weggelassen). Zuletzt folgt ein Code für ein
Gerät im selben LAN. Danach wartet die Einladung.
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

Weil der Befehl mit sudo läuft, wird der Benutzer, der sudo aufgerufen hat,
Operator des NAS.
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
  Devices       1 other
  Names         laptop.home.juist
  Freshness     unchecked: no voucher
  Ports         udp/41643
  Schema        20
  Updated       just now
$ juist devices
NAME                  IPV4         REACHED  SCHEMA  ROLES
laptop (this device)  198.18.36.1  -        20      -
nas                   198.18.36.2  direct   20      -
$ ping 198.18.36.2
```

`juist devices` listet die Geräte auf, und auch `ping nas.home.juist`
klappt.
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
Adresse, etwa ein VPS, braucht den offenen Port 41643/udp.

## Hinweise

- `juist create home` nennt das Netz `home`. Das Gerät bekommt den
  Rechnernamen, es sei denn, du gibst `--device` an.
- Der IPv4-Bereich ist ein zufälliges `/22` aus `198.18.0.0/15`, etwa
  `198.18.36.0/22`. Mit `--ipv4` legst du ihn selbst fest.
- Der Code funktioniert nur im selben LAN, und schon ein falscher Versuch
  macht ihn ungültig. Der Link funktioniert dann weiterhin.
- Eine Einladung gilt eine Stunde und für genau ein Gerät. Für das nächste
  rufst du `juist invite` erneut auf.
- Die Zeile `Break-glass` erscheint nur dieses eine Mal und wird nirgends
  gespeichert. Lege sie in einen Passwortmanager oder auf Papier, getrennt
  von den Admin-Schlüsseln: Mit ihr beendest du das Netz, wenn nicht mehr
  genug Admin-Schlüssel übrig sind, um es zu ändern
  ([Das Netz beenden]({{< relref "docs/network-changes" >}}#das-netz-beenden)).
- Das Netz hat noch keinen **Voucher**. Ein Voucher ist ein Gerät, das
  stündlich bestätigt, dass der Stand des Netzes aktuell ist. Das begrenzt,
  wie lange ein von den anderen abgeschnittenes Gerät noch mit einem
  entfernten sprechen kann. Gib die
  Rolle nur Geräten, die ständig laufen (`juist grant GERÄT voucher`);
  `juist create --voucher` macht schon das erste Gerät dazu. Mehr dazu unter
  [Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers).

## Fehlersuche

| Was du siehst | Was du tun kannst |
|---|---|
| `juist: run as alice, without sudo: the admin key belongs in your keystore` | Ruf `juist create` ohne sudo auf. |
| `juist0 · not running` in `juist status` | `sudo systemctl enable --now juistd` |
| `read-only; to manage this device …` | einmal `sudo juist set --operator=$USER` |
| `warning: code voided: wrong guess from …` | Tritt mit dem Link bei, der weiterhin gilt. Kam der Fehlversuch nicht von deinem Gerät, kennt jemand anderes die Einladung. |
| `juist: words not confirmed; nothing signed` | Wichen die Wörter voneinander ab, ist das anfragende Gerät nicht das eingeladene. Starte eine neue Einladung. |
| `no answer from a device` in `juist health` | Das Gerät ist offline, oder sein Port 41643/udp ist gesperrt. |
| `no tunnel traffic from a device` | Öffne 41643/udp auf einem Gerät mit öffentlicher Adresse, oder gib einem Gerät die Rolle `relay`. |

Weitere Fälle stehen unter [Fehlersuche]({{< relref "docs/troubleshooting" >}}).

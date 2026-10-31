---
title: Geräte einladen
linkTitle: Geräte einladen
description: Ein Gerät per Code oder Link ins Netz holen, die vier Wörter vergleichen und ihm gleich beim Beitritt eine Rolle geben.
lead: Mit einer Einladung tritt genau ein neues Gerät dem Netz bei. Du startest sie auf dem Gerät eines Admins, und das neue Gerät tritt mit dem Code oder dem Link bei, den sie ausgibt.
---

## So funktioniert eine Einladung

Eine **Einladung** ist ein kurzlebiges Geheimnis, mit dem ein neues Gerät
beitritt. `juist invite` gibt sie als Code und als Link aus und wartet. Auf
dem neuen Gerät rufst du `sudo juist join` mit einem der beiden auf.

Einladen kann nur das Gerät eines
[Admins]({{< relref "docs/how-it-works" >}}#admins), denn die Aufnahme ist
eine signierte Änderung. Bevor etwas signiert wird, zeigen beide Geräte vier
Wörter zum Vergleichen. Sie belegen, dass das Gerät, das beitreten will, das
eingeladene ist.

## Code oder Link

| | Code | Link |
|---|---|---|
| Beispiel | `42-drumbeat-tolerance-glucose` | `'juist:Kx7…@192.168.1.20:41642'` |
| Funktioniert | nur im selben LAN | überall |
| Nach einem Fehlversuch | ist der Code ungültig | bleibt alles gültig |

Der **Code** besteht aus einer Zahl und drei Wörtern und lässt sich
vorlesen. Die Zahl unterscheidet Einladungen, die drei Wörter sind das
Geheimnis. Das neue Gerät sucht das einladende im LAN und verbindet sich mit
ihm auf TCP-Port 41642. Kann eine Firewall diesen Port blockieren, gibt
`juist invite` den Befehl aus, der ihn öffnet, etwa
`hint: the firewall may block the device: sudo ufw allow 41642/tcp`.

Mit dem Code gibt es genau einen Versuch. Nach einem Fehlversuch meldet das
einladende Gerät `warning: code voided: wrong guess from …` und lehnt auch
den richtigen Code ab. Der Link funktioniert weiter.

Der **Link** enthält ein 128-Bit-Geheimnis, die Adressen des einladenden
Geräts und den Schlüssel des einladenden Admins. Kopiere ihn vollständig
samt Anführungszeichen, damit die Shell ihn nicht verändert.

Im Terminal zeigt `juist invite` den Link auch als QR-Code. Ein Telefon tritt
bei, indem die [Android-App]({{< relref "docs/android" >}}) ihn scannt oder
du den Code eintippst. Ist das Fenster zu schmal für den QR-Code, sagt juist
das.

Code und Link verfallen, sobald ein Gerät beigetreten ist oder die Einladung
abläuft. Eine Einladung gilt eine Stunde; `--expires 2h` ändert das, bis
`7d`.

## Ein Gerät einladen

{{< step on="dem Gerät eines Admins" >}}
Starte die Einladung. Soll das neue Gerät anders heißen, gib den Namen hier
an:

```sh
juist invite nas
```

Ohne Namen behält das Gerät seinen Rechnernamen. Ist der Name schon an ein
anderes Mitglied vergeben, hängt juist eine Zahl an.
{{< /step >}}
{{< step on="nas" as="das neue Gerät" >}}
Tritt im selben LAN mit dem Code bei, von überall sonst mit dem Link:

```sh
sudo juist join 42-drumbeat-tolerance-glucose
```

Das neue Gerät zeigt vier Wörter an: `tell the inviting admin these words:`.
{{< /step >}}
{{< step on="dem Gerät eines Admins" >}}
Vergleiche sie mit den Wörtern, die die Einladung anzeigt, und antworte:

```console
nas wants to join; compare with the words it shows:
  atlas-amulet-banjo-asteroid
same? [y/N] y
admitting nas (nid:fcRW83T_…)
admitted nas at 198.18.36.2
nas joined
```
{{< /step >}}

## Die vier Wörter

Die Wörter umfassen die Identität des neuen Geräts und alle seine
Schlüssel. Hat sich ein anderes Gerät dazwischengeschaltet, weichen sie ab.
Ein Gerät dazwischen kann nicht nach passenden Wörtern suchen, weil jede
Seite ihren Teil festlegt, bevor sie den der anderen kennt.

Weichen die Wörter ab, antworte mit `n`. Die Einladung signiert nichts:
`juist: words not confirmed; nothing signed`. Starte eine neue Einladung und
finde heraus, welches Gerät beitreten wollte.

`juist invite --yes` überspringt den Vergleich. Nutze es nur, wo du ohnehin
nicht vergleichen kannst, etwa in einem Skript.

## Mit einer Rolle einladen

Eine Einladung kann dem neuen Gerät gleich beim Beitritt eine
[Rolle]({{< relref "docs/how-it-works" >}}#roles) geben:

| Option | Das neue Gerät wird |
|---|---|
| `--relay` | ein Relay, das Verkehr für Geräte weiterleitet, die sich nicht direkt erreichen ([Relays]({{< relref "docs/relays" >}})) |
| `--voucher` | ein Voucher, der stündlich bestätigt, dass der Stand des Netzes aktuell ist ([Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)) |
| `--ingress` | ein Ingress, der Verbindungen aus dem Internet für veröffentlichte Namen annimmt ([Dienste veröffentlichen]({{< relref "docs/publishing" >}})) |
| `--service NAME` | ein Service-Mitglied, das `NAME` veröffentlicht und keine Verbindungen zu anderen Geräten öffnen kann ([Service-Mitglieder]({{< relref "docs/service-member" >}})) |

So lädst du einen VPS als Ingress des Netzes ein:

```console
$ juist invite vps --ingress
invite to "home" as ingress, expires in 1h; on the new device:
```

`--ingress` und `--voucher` schließen sich aus, und `--service` lässt sich
mit keiner anderen Option kombinieren. Andere Rollen wie `exit` vergibst du
nach dem Beitritt mit `juist grant`.

## Über NAT hinweg

Der Link funktioniert auch, wenn beide Geräte an verschiedenen Orten hinter
NAT stehen. Das neue Gerät probiert zuerst die Adressen aus dem Link. Kommt
es nicht durch, finden sich beide über den öffentlichen BitTorrent-DHT, und
das neue Gerät meldet
`no direct answer; meeting through the DHT (up to a minute)`.

Hat das Netz ein Relay und steht das einladende Gerät hinter NAT, wartet die
Einladung auch beim Relay: `juist invite` meldet
`meets through relay 203.0.113.7:41645 where this device is unreachable`. Das
Geheimnis der Einladung sieht das Relay nie.

Scheitern kann das nur, wenn beide NATs symmetrisch sind, also für jedes Ziel
einen neuen Port wählen. Dann tritt über einen Internetanschluss bei, von dem
aus das einladende Gerät erreichbar ist, oder richte zuerst ein
[Relay]({{< relref "docs/relays" >}}) ein.

## Gut zu wissen

- Eine Einladung gilt für genau ein Gerät. Für das nächste rufst du
  `juist invite` erneut auf.
- `--no-lan` gibt nur den Link aus. `--no-dht` hält die Einladung aus dem
  öffentlichen DHT heraus. `--port` wählt einen anderen TCP-Port als 41642.
- `sudo juist join` macht den sudo-Benutzer zum
  [Operator]({{< relref "docs/operator" >}}) des Geräts. `--operator` nennt
  einen anderen Benutzer, `--name` den Namen des Geräts.
- Braucht eine Änderung die Stimmen mehrerer Admins, wartet die Einladung auf
  die übrigen, und das neue Gerät zeigt `waiting for approval (1 of 2 votes)`.
  Die Wartezeit zählt zur Laufzeit der Einladung.
- Auf einem Gerät in mehreren Netzen nennst du das Netz: `juist invite work`.
- Mit [Zugriffsregeln]({{< relref "docs/access" >}}) bekommt das neue Gerät
  keinen Verkehr, bis eine Regel es nennt. `juist invite` sagt das in einer
  `hint:`-Zeile.

## Fehlersuche


| Was du siehst | Was du tun kannst |
|---|---|
| `juist: no admin key of this network here` | Lade vom Gerät eines Admins aus ein. |
| `warning: code not announced on the LAN (…); use the link` | Tritt mit dem Link bei. |
| `warning: code voided: …` | Tritt mit dem Link bei. Kam der Fehlversuch nicht von deinem Gerät, kennt jemand anderes die Einladung. |
| `juist: invite expired` | Starte eine neue Einladung. Musstest du auf andere Admins warten, gib ein längeres `--expires` an. |
| `juist: cannot reach the inviting device, …` | Prüfe, ob die Einladung noch läuft. Stehen beide Geräte hinter NAT, tritt über einen Internetanschluss bei, von dem aus das einladende Gerät erreichbar ist, oder richte zuerst ein Relay ein. |
| `juist: comparing the device's words needs a terminal; pass --yes to skip` | Ruf `juist invite` in einem Terminal auf, oder gib `--yes` an, wenn du nicht vergleichen kannst. |
| `juist: … the inviting device runs an incompatible version of juist` | Aktualisiere juist auf beiden Geräten und lade dann neu ein. |
| `juist: the invite link is from an older juist; ask for a new one` | Aktualisiere juist auf dem einladenden Gerät und starte eine neue Einladung. |

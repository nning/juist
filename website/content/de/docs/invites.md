---
title: Geräte einladen
linkTitle: Geräte einladen
description: Ein Gerät per Code oder Link ins Netz holen, die vier Wörter vergleichen und ihm gleich beim Beitritt eine Rolle geben.
lead: Mit einer Einladung tritt genau ein neues Gerät dem Netz bei. Du startest sie auf dem Gerät eines Admins, und das neue Gerät tritt mit dem Code oder dem Link bei, den sie ausgibt.
---

## So funktioniert eine Einladung

Eine **Einladung** ist ein kurzlebiges Geheimnis, mit dem ein neues Gerät dem
Netz beitritt. `juist invite` gibt sie in zwei Formen aus, als Code und als
Link, und wartet dann. Auf dem neuen Gerät rufst du `sudo juist join` mit
einem der beiden auf.

Einladen kann nur das Gerät eines Admins, denn die Aufnahme eines Geräts ist
eine Änderung am Netz, die ein Admin signieren muss. Ein **Admin** ist ein
Mensch, der mit seinem Schlüssel Änderungen signiert, siehe
[So funktioniert juist]({{< relref "docs/how-it-works" >}}).

Bevor irgendetwas signiert wird, zeigen beide Geräte vier Wörter, die du
vergleichst. Daran erkennst du, dass das Gerät, das beitreten will, wirklich
das eingeladene ist.

## Code oder Link

| | Code | Link |
|---|---|---|
| Beispiel | `42-drumbeat-tolerance-glucose` | `'juist:Kx7…@192.168.1.20:41642'` |
| Funktioniert | nur im selben LAN | überall |
| Nach einem Fehlversuch | ist der Code ungültig | bleibt alles gültig |

Der **Code** besteht aus einer Zahl und drei Wörtern und ist kurz genug, um
ihn vorzulesen oder abzutippen. Die Zahl unterscheidet Einladungen
voneinander und ist nicht geheim, die drei Wörter schon. Das neue Gerät sucht
das einladende Gerät, indem es im LAN nachfragt, und verbindet sich dann mit
ihm auf TCP-Port 41642. Kann eine Firewall auf dem einladenden Gerät diesen
Port blockieren, gibt `juist invite` den Befehl aus, der ihn öffnet, etwa
`hint: the firewall may block the device: sudo ufw allow 41642/tcp`.

Mit dem Code gibt es genau einen Versuch. Nach einem Fehlversuch meldet das
einladende Gerät `warning: code voided: wrong guess from …` und lehnt danach
auch den richtigen Code ab. Der Link funktioniert aber weiterhin.

Der **Link** enthält ein 128-Bit-Geheimnis, die Adressen des einladenden
Geräts und den Schlüssel des einladenden Admins, der das neue Gerät an dessen
Signatur bindet. Kopiere ihn vollständig samt Anführungszeichen, denn er
enthält Zeichen, die eine Shell sonst verändern würde.

Im Terminal zeichnet `juist invite` den Link zusätzlich als QR-Code, über der
Zeile mit `juist join` für den Link. Eine Kamera liest aus dem QR-Code nur den
Link, ohne den Befehl. Der Code fürs LAN steht ganz unten, damit er auch in
einem Fenster sichtbar bleibt, das niedriger ist als der QR-Code. Geht die
Ausgabe nicht in ein Terminal oder ist das Fenster zu schmal, fehlt der
QR-Code. Im zweiten Fall sagt juist das:
`no qr code: the terminal is narrower than 59 columns`.

Ein Telefon tritt bei, indem die [Android-App]({{< relref "docs/android" >}})
den QR-Code scannt oder du den Code in sie eintippst.

Code und Link verfallen, sobald ein Gerät beigetreten ist oder die Einladung
abläuft. Eine Einladung gilt eine Stunde, es sei denn, du gibst `--expires`
an, etwa `--expires 2h`. Höchstens sind `7d` möglich.

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

Die Wörter umfassen die Identität des neuen Geräts und alle seine Schlüssel.
Hat sich ein anderes Gerät dazwischengeschaltet, weichen die Wörter ab.
Jede Seite legt ihren Teil der Wörter fest, bevor sie den Teil der anderen
kennt. Ein Gerät dazwischen kann deshalb nicht nach passenden Wörtern suchen.

Weichen die Wörter voneinander ab, antworte mit `n`. Die Einladung signiert
dann nichts: `juist: words not confirmed; nothing signed`. Starte eine neue
Einladung und finde heraus, welches Gerät beitreten wollte.

`juist invite --yes` nimmt das Gerät auf, ohne zu vergleichen. Damit entfällt
diese Prüfung. Nutze die Option also nur, wo du ohnehin nicht vergleichen
könntest, etwa in einem Skript.

## Mit einer Rolle einladen

Mit einer **Rolle** übernimmt ein Gerät eine zusätzliche Aufgabe im Netz.
Eine Einladung kann dem neuen Gerät gleich beim Beitritt eine Rolle geben:

| Option | Das neue Gerät wird |
|---|---|
| `--relay` | ein Relay, das Verkehr für Geräte weiterleitet, die sich nicht direkt erreichen ([Relays]({{< relref "docs/relays" >}})) |
| `--voucher` | ein Voucher, der stündlich bestätigt, dass der Stand des Netzes aktuell ist ([Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)) |
| `--ingress` | eine Ingress, die Verbindungen aus dem Internet für veröffentlichte Namen annimmt ([Dienste veröffentlichen]({{< relref "docs/publishing" >}})) |
| `--service NAME` | ein Service-Mitglied, das `NAME` unter der Domain des Netzes veröffentlicht und selbst keine Verbindungen zu anderen Geräten öffnen kann ([Dienste veröffentlichen]({{< relref "docs/publishing" >}}#keeping-the-server-away-from-your-network)) |

So lädst du einen VPS ein, der die Ingress des Netzes werden soll:

```console
$ juist invite vps --ingress
invite to "home" as ingress, expires in 1h; on the new device:
```

Eine Ingress kann kein Voucher sein, `--ingress` und `--voucher` schließen
sich also aus. Ein Service-Mitglied hat keine weitere Rolle, `--service` lässt
sich daher mit keiner der anderen Optionen kombinieren. Andere Rollen wie
`exit` vergibst du nach dem Beitritt mit `juist grant`.

## Über NAT hinweg

Der Link funktioniert auch, wenn beide Geräte an verschiedenen Orten hinter
NAT stehen. Das neue Gerät probiert zuerst die Adressen aus dem Link. Kommt
es darüber nicht durch, finden sich beide über den öffentlichen
BitTorrent-DHT, und das neue Gerät meldet
`no direct answer; meeting through the DHT (up to a minute)`. Den größten
Teil dieser Minute braucht der Beitritt zum DHT.

Hat das Netz ein Relay und steht das einladende Gerät hinter NAT, wartet die
Einladung zusätzlich beim Relay, und der Link enthält dessen Adresse.
`juist invite` meldet dann
`meets through relay 203.0.113.7:41645 where this device is unreachable`. Das
Geheimnis der Einladung bekommt das Relay nie zu sehen.

Scheitern kann das nur, wenn beide NATs symmetrisch sind, also für jedes Ziel
einen neuen Port wählen. Dann hast du zwei Möglichkeiten:

- Du trittst über einen Internetanschluss bei, von dem aus das einladende
  Gerät erreichbar ist.
- Du richtest zuerst ein [Relay]({{< relref "docs/relays" >}}) ein und lädst
  dann neu ein.

## Hinweise

- Eine Einladung gilt für genau ein Gerät. Für das nächste rufst du
  `juist invite` erneut auf.
- `--no-lan` gibt nur den Link aus, keinen Code. `--no-dht` hält die
  Einladung aus dem öffentlichen DHT heraus. Mit `--port` wählst du einen
  anderen TCP-Port als 41642.
- `sudo juist join` macht den Benutzer, der sudo aufgerufen hat, zum
  [Operator]({{< relref "docs/operator" >}}) des Geräts, also zu dem lokalen
  Benutzer, der es ohne sudo verwaltet. Mit `--operator` bestimmst du einen
  anderen. `--name` legt fest, unter welchem Namen das Gerät beitritt.
- Braucht das Netz die Stimmen mehrerer Admins, wartet die Einladung auf die
  übrigen, und das neue Gerät zeigt `waiting for approval (1 of 2 votes)`.
  Diese Wartezeit zählt zur Laufzeit der Einladung.
- Ist ein Gerät in mehreren Netzen, gibst du an, welches gemeint ist:
  `juist invite work`.
- Hat das Netz [Zugriffsregeln]({{< relref "docs/access" >}}), lassen sie
  keinen Verkehr von oder zu dem neuen Gerät durch, bis eine Regel es nennt.
  `juist invite` weist in einer `hint:`-Zeile darauf hin.

## Fehlersuche


| Was du siehst | Was du tun kannst |
|---|---|
| `juist: no admin key of this network here` | Lade vom Gerät eines Admins aus ein. |
| `warning: code not announced on the LAN (…); use the link` | Tritt mit dem Link bei. |
| `warning: code voided: …` | Tritt mit dem Link bei. Kam der Fehlversuch nicht von deinem Gerät, kennt jemand anderes die Einladung. |
| `juist: invite expired` | Starte eine neue Einladung. Musstest du auf andere Admins warten, gib ein längeres `--expires` an. |
| `juist: cannot reach the inviting device, …` | Prüfe, ob die Einladung noch läuft. Stehen beide Geräte hinter NAT, tritt über einen Internetanschluss bei, von dem aus das einladende Gerät erreichbar ist, oder richte zuerst ein Relay ein. |
| `juist: comparing the device's words needs a terminal; pass --yes to skip` | Ruf `juist invite` in einem Terminal auf, oder gib `--yes` an, wenn du nicht vergleichen kannst. |

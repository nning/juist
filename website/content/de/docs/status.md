---
title: Status und Geräte
linkTitle: Status und Geräte
description: Nachsehen, ob ein Gerät verbunden ist, was zu tun ist, welche Geräte im Netz sind und welche Änderungen es gab.
lead: Vier Befehle zeigen dir, wie es um dein Netz steht. juist status zeigt dieses Gerät, juist health alles, worum du dich kümmern solltest, juist devices listet alle Geräte auf, und juist log zeigt jede Änderung und wer sie bestätigt hat.
---

Dein Netz besteht aus Geräten, die zusammengehören, und jedes davon ist ein
**Mitglied**. Jedes Mitglied hat eine eigene Kopie des Logs, also der
signierten Liste aller Änderungen (siehe
[So funktioniert juist]({{< relref "docs/how-it-works" >}})). Die Befehle auf
dieser Seite lesen dieses Log und fragen den Daemon `juistd`, das Programm,
das die Tunnel aufrecht hält, nach dem aktuellen Stand.

Scheint etwas nicht zu stimmen, fang mit `juist health` an. Der Befehl nennt
jedes Problem und gibt in einer Zeile `hint:` den Befehl aus, der es behebt.

## Ein Gerät prüfen

{{< step on="laptop" >}}
Sieh nach, ob dieses Gerät verbunden ist:

```sh
juist status
```

```console
$ juist status
home · connected
  This device   laptop  198.18.36.1  fd4c:8a21:e3f:5b1a:9d02:c4e7:31f8:a6b0
  Devices       3 others
  Relays        1 available, via vps
  Names         home.juist
  Freshness     vouched 12m ago, valid 48h
  Ports         udp/41643
  Schema        18
  Updated       just now
```

Die erste Zeile nennt das Netz und seinen Zustand, darunter folgen die
Einzelheiten. Ist etwas zu tun, verweisen höchstens zwei Hinweise weiter:

```console
hint: 1 change waits for your vote: juist approve
hint: 3 warnings: juist health
```
{{< /step >}}

Ist das Gerät in mehreren Netzen, nennt der zweite Hinweis das Netz, etwa
`juist health work`. `juist status` selbst meldet nur, was das Netz anhält:
einen Fork- oder Rollback-Alarm oder ein Schema, das diese Version von juist nicht lesen
kann.

In der ersten Zeile steht einer dieser Zustände:

| Zustand | Bedeutung |
|---|---|
| `connected` | alles funktioniert |
| `waiting for peers` | es gibt andere Geräte, aber noch keines hat sich gemeldet |
| `no tunnel up` | andere Geräte sind bekannt, aber durch keinen Tunnel zu ihnen fließt Verkehr |
| `limited` | der Stand dieses Geräts ist womöglich veraltet, deshalb hält es nur Tunnel zu Vouchern (siehe `Freshness` unten) |
| `disabled` | das Netz wurde mit einem Break-glass-Geheimnis beendet; mit `juist reset` beginnst du von vorn |
| `removed` | dieses Gerät gehört nicht mehr zum Netz |
| `juistd not running` | der Daemon läuft nicht, starte ihn (siehe [Fehlersuche]({{< relref "docs/troubleshooting" >}})) |

## Was die Zeilen bedeuten

- `This device`: Name und Adressen dieses Geräts im Netz, erst IPv4, dann IPv6.
- `Devices`: wie viele andere Geräte es gibt und zu wie vielen davon bei der
  letzten Prüfung kein Tunnel Verkehr trug; `juist devices` sagt, warum.
  juistd prüft alle 30 Sekunden. Haben beide Enden ein Relay, prüft es einen
  ruhigen Tunnel nur alle 5 Minuten, damit das Funkmodul eines Laptops
  schlafen kann.
- `Relays`: wie viele Geräte Verkehr weiterleiten dürfen und welches davon dieses Gerät nutzt. Ein [Relay]({{< relref "docs/relays" >}}) leitet Verkehr zwischen zwei Geräten weiter, die sich nicht direkt erreichen.
- `HTTPS`: auf einem Gerät, das nur HTTPS sendet, die Relays auf Port 443, über die es läuft, und sein Proxy. Siehe [Nur HTTPS]({{< relref "docs/https-only" >}}).
- `Relay name`: der öffentliche Name, den das Relay dieses Geräts auf Port 443 bedient. root und der Operator sehen außerdem, ob es ihn schon bedient.
- `Exit node`: über welches Gerät der Internetverkehr dieses Geräts läuft, falls überhaupt. Siehe [Exit-Nodes]({{< relref "docs/exit-nodes" >}}).
- `Names`: die Domain, unter der dieses Gerät die anderen findet, etwa `home.juist`, oder der Grund, warum das nicht geht. Siehe [Namen]({{< relref "docs/names" >}}).
- `Freshness`: wann ein Voucher zuletzt bestätigt hat, dass dieses Gerät den
  aktuellen Stand des Netzes kennt, und wie lange diese Bestätigung gilt. Ein
  Voucher ist ein Gerät, das diese Bestätigung im Auftrag des Netzes stündlich
  ausstellt. Nach 48 Stunden ohne Bestätigung steht dort
  `expired; vouchers only`. Einen Tag vorher warnt `juist health`. Ist kein
  Gerät Voucher, steht dort `unchecked: no voucher`, und dürfen mindestens
  zwei Geräte Verkehr weiterleiten, schlägt `juist health` sie als Voucher vor.
  Siehe [Geräte entfernen]({{< relref "docs/remove" >}}).
- `Published`: die veröffentlichten Namen, die dieses Gerät bedient, oder
  warum es sie nicht bedient. Siehe [Dienste veröffentlichen]({{< relref "docs/publishing" >}}).
- `Ingress`: auf einer Ingress, ob sie läuft, welche Namen sie bedient,
  welche Ports sie per TCP weiterreicht und welche Ports ein anderes Programm
  belegt.
- `Sharing`: wie viele Freigaben dieses Gerät hat (`juist share` listet sie
  auf), oder warum niemand sie erreicht.
- `Ports`: die Ports, auf denen juistd lauscht. `udp/41643` ist der für die Tunnel.
- `Schema`: die Version des Formats, in dem das Log des Netzes steht. Kennt
  diese Version von juist eine neuere, folgt sie gelb in Klammern, etwa
  `18 (19)`; auf einem Gerät mit Admin-Schlüssel sagt `juist health` dann,
  wie du es anhebst (siehe [Admins]({{< relref "docs/admins" >}})).
- `Updated`: wann juistd zuletzt einen neuen Stand des Netzes übernommen hat.

Zeilen wie `Subnets`, `Published` oder `Renumbering` erscheinen nur, wenn
die jeweilige Funktion genutzt wird.

## Was zu tun ist

`juist health` sagt, worum du dich auf diesem Gerät kümmern solltest, jede
Warnung mit einem `hint:`, der sie behebt, und welche Geräte es nicht
erreicht:

```console
$ juist health
warning: log sync to vps fails in the tunnel: tcp/41644 does not answer there
hint: where it runs Linux: sudo ufw allow in on juist0, or add juist0 to firewalld's trusted zone
no answer from phone: offline, or udp/41643 blocked
```

Eine schlichte Zeile wie `no answer from phone` verlangt nichts, solange das
Gerät aus ist. Nach den Warnungen folgen die Änderungen, die auf deine Stimme
warten (siehe [Admins]({{< relref "docs/admins" >}})), und auf einem Gerät
mit Admin-Schlüssel, wie du das Schema des Netzes anhebst. Ist nichts zu tun,
sagt der Befehl das:

```console
$ juist health
nothing needs attention
```

Ist das Gerät in mehreren Netzen, gibt `juist health` jedes Netz unter seinem
Namen aus.

## Die Geräte auflisten

`juist devices` listet alle Geräte in einer Tabelle auf:

```console
$ juist devices
NAME                  IPV4         REACHED  SCHEMA  ROLES
laptop (this device)  198.18.36.1  -        18      -
nas                   198.18.36.2  direct   18      voucher, names, publishes
vps                   198.18.36.3  direct   18      voucher, relay
phone                 198.18.36.4  relayed  18      -
```

`ROLES` zeigt für jedes Gerät:

- die Rollen, die das Netz ihm gegeben hat, etwa `voucher`, `relay` oder `exit`;
- seine Subnetze;
- `names`, wenn öffentliche Namen auf das Gerät zeigen ([`juist names`]({{< relref "docs/names" >}}) listet sie auf);
- `publishes`, wenn es Namen veröffentlicht ([`juist publish`]({{< relref "docs/publishing" >}}) listet sie auf);
- `-`, wenn nichts davon zutrifft.

In einem schmalen Terminal brechen die Rollen innerhalb ihrer Spalte um. In
einem noch schmaleren, etwa auf dem Handy, belegt jedes Gerät mehrere Zeilen.

`REACHED` gibt an, wie juistd das Gerät bei der letzten Prüfung erreicht hat:

| `REACHED` | Bedeutung |
|---|---|
| `direct` | ein direkter Tunnel funktioniert |
| `relayed` | der Tunnel läuft über ein Relay |
| `outdated` | auf dem Gerät läuft ein älteres juist, und bis es aktualisiert ist, ist es nicht erreichbar |
| `no answer` | das Gerät hat nicht geantwortet, weil es offline ist oder eine Firewall es blockiert |
| `offline`, `offline, heard 3h ago` | das Gerät ist wahrscheinlich offline und hat sich seitdem nicht gemeldet |
| `not heard from` | das Gerät hat noch nicht mitgeteilt, wo es erreichbar ist |
| `not checked yet` | juistd hat noch nicht nachgesehen |
| `not connected` | das Gerät hat sich gemeldet, aber es gibt keinen Tunnel, etwa weil der Stand dieses Geräts veraltet ist |
| `-` | dieses Gerät selbst |

`SCHEMA` ist das neueste Schema, das das juist eines Geräts kennt, so wie das
Gerät es ankündigt. Es ist gelb, wo es älter ist als das dieses Geräts, und
`-`, wo dieses Gerät noch keine Ankündigung von ihm gehört hat. Läuft juistd
nicht oder hat es keine gehört, fehlt die Spalte.

Gelten [Zugriffsregeln]({{< relref "docs/access" >}}), zeigt `juist devices`
nur dieses Gerät und die Mitglieder, zu denen es einen Tunnel hat, und endet mit
`hint: 2 more devices the access policy keeps apart from this one: juist devices --all`.

`juist devices -6` zeigt zusätzlich die IPv6-Adresse jedes Geräts,
`juist devices --keys` seinen Identitätsschlüssel. Auch
[`juist remove`]({{< relref "docs/remove" >}}) akzeptiert diesen Schlüssel.

## Alle Änderungen ansehen

```console
$ juist log
   0  network creation                             K2JS2DNGYZWZ
      approved by alice
   1  device admission: nas                        EU7V5XCUUOSO
      approved by alice
   2  device admission: vps                        QH4T7MWD2LXA
      approved by alice
   3  change of a device's roles or subnets: vps   MMOPGHJRKJ7D
      approved by alice
4 changes
```

Jeder Eintrag ist eine Änderung, darunter stehen die Admins, die sie mit
ihrem Schlüssel bestätigt haben. Ein Admin ist eine Person, deren Schlüssel
Änderungen bestätigen darf (siehe [Admins]({{< relref "docs/admins" >}})).

`juist log show` zeigt, was eine einzelne Änderung bewirkt hat und welche
Schlüssel sie signiert haben. Du gibst sie mit ihrer Nummer an, mit -N vom
Ende her gezählt (`-1` ist die neueste) oder mit dem Anfang ihres Hashes:

```console
$ juist log show 3
   3  change of a device's roles or subnets: vps
      gives vps (nid:QH4T7MWD…) the role relay
      approved by alice, with nid:Kc3vR8dE…
      hash MMOPGHJRKJ7DTZ2QWLQ6N5LXGZ4VQ3RJ4M2B7ZPXS2YQFG6C5WDA
```

Jede Änderung wird gegenüber dem Netz beschrieben, wie es direkt davor war.
Eine Änderung der Zugriffsregeln erscheint deshalb als Diff. Uhrzeiten
enthält das Log nicht, denn keine Änderung trägt ein signiertes Datum.
`juist log verify` prüft das gesamte Log noch einmal.

## Das Log des Daemons

```sh
journalctl -u juistd
```

Hier steht, was juistd selbst meldet. Ein zweites Netz auf demselben Gerät
hat einen eigenen Daemon, `juistd@juist1`, mit eigenem Log.

## Hinweise

- Jeder lokale Benutzer darf `juist status` und `juist health` ausführen. Wer
  weder root noch [Operator]({{< relref "docs/operator" >}}) des Geräts ist,
  sieht in `juist health` einen Hinweis `read-only`.
- `juist devices`, `juist log` und alle anderen Befehle sind root und dem Operator vorbehalten.
- Ist ein Gerät in [mehreren Netzen]({{< relref "docs/networks" >}}), zeigen
  `juist status`, `juist health` und `juist devices` alle Netze nacheinander.
  `juist devices work` zeigt nur eines.

## Fehlersuche

`juist health` gibt Warnungen aus, jeweils mit einer Zeile `hint:` darunter.
Die häufigsten und was du dagegen tun kannst, stehen unter
[Fehlersuche]({{< relref "docs/troubleshooting" >}}).

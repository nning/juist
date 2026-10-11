---
title: Status und Geräte
linkTitle: Status und Geräte
description: Nachsehen, ob ein Gerät verbunden ist, welche Geräte im Netz sind und welche Änderungen es gab.
lead: Drei Befehle zeigen dir, wie es um dein Netz steht. juist status zeigt dieses Gerät und alles, worum du dich kümmern solltest, juist devices listet alle Geräte auf, und juist log zeigt jede Änderung und wer sie bestätigt hat.
---

## Worum es geht

Dein Netz besteht aus Geräten, die zusammengehören, und jedes davon ist ein
**Mitglied**. Jedes Mitglied hat eine eigene Kopie des Logs, also der
signierten Liste aller Änderungen (siehe
[So funktioniert juist]({{< relref "docs/how-it-works" >}})). Die Befehle auf
dieser Seite lesen dieses Log und fragen beim Daemon `juistd` nach, dem
Programm, das die Tunnel aufrecht hält, wie es gerade aussieht.

Scheint etwas nicht zu stimmen, fang mit `juist status` an. Der Befehl nennt
das Problem und gibt in einer Zeile `hint:` den Befehl aus, der es behebt.

## Ein Gerät prüfen

{{< step on="laptop" >}}
Sieh nach, ob dieses Gerät verbunden ist und ob etwas zu tun ist:

```sh
juist status
```

```console
$ juist status
home · connected
  This device   laptop  198.18.36.1  fd4c:8a21:e3f:5b1a:9d02:c4e7:31f8:a6b0
  Devices       3 others, all heard from
  Tunnels       3 of 3 live
  Post-quantum  every tunnel: 3 by pair keys
  Relays        1 available, via vps
  Names         home.juist
  Freshness     vouched 12m ago, valid 48h
  Ports         udp/41643
  Updated       just now
```

Die erste Zeile nennt das Netz und seinen Zustand. Darunter folgen die
Einzelheiten und zuletzt etwaige Warnungen, jede mit einem Hinweis.
{{< /step >}}

In der ersten Zeile steht einer dieser Zustände:

| Zustand | Bedeutung |
|---|---|
| `connected` | alles funktioniert |
| `waiting for peers` | es gibt andere Geräte, aber noch keines hat sich gemeldet |
| `no tunnel up` | andere Geräte sind bekannt, aber durch keinen Tunnel zu ihnen fließt Verkehr |
| `limited` | der Stand dieses Geräts ist womöglich veraltet, deshalb hält es nur Tunnel zu Vouchern (siehe Frische unten) |
| `disabled` | das Netz wurde mit einem Break-glass-Geheimnis beendet; mit `juist reset` beginnst du von vorn |
| `removed` | dieses Gerät gehört nicht mehr zum Netz |
| `juistd not running` | der Daemon läuft nicht, starte ihn (siehe [Fehlersuche]({{< relref "docs/troubleshooting" >}})) |

## Was die Zeilen bedeuten

- `This device`: Name und Adressen dieses Geräts im Netz, erst IPv4, dann IPv6.
- `Devices`: wie viele andere Geräte es gibt und wie viele davon sich gemeldet haben.
- `Tunnels`: durch wie viele Tunnel bei der letzten Prüfung Verkehr floss. juistd prüft alle 30 Sekunden, fragt einen ruhigen Tunnel aber nur alle 5 Minuten, wenn beide Enden ein Relay haben, damit das Funkmodul eines Laptops schlafen kann.
- `Post-quantum`: wie viele Tunnel einen Schlüssel in ihre Handshakes
  mischen, den ein Quantencomputer nicht herausfinden kann, und welchen: einen
  Pair Key, den nur die beiden Geräte haben, oder den Gruppenschlüssel, den
  jedes Mitglied ableiten könnte, wie in den ersten Sekunden eines Tunnels und
  zu einem Gerät, das hinter dem Netz zurück ist. Eine Warnung nennt einen
  Tunnel ohne. Siehe [Sicherheit]({{< relref "docs/security" >}}).
- `Relays`: wie viele Geräte Verkehr weiterleiten dürfen und welches davon dieses Gerät nutzt. Ein [Relay]({{< relref "docs/relays" >}}) leitet Verkehr zwischen zwei Geräten weiter, die sich nicht direkt erreichen.
- `HTTPS`: auf einem Gerät, das nur HTTPS sendet, die Relays auf 443, über die es läuft, und sein Proxy. Siehe [Nur HTTPS]({{< relref "docs/https-only" >}}).
- `Relay name`: der öffentliche Name, den das Relay dieses Geräts auf 443 bedient, und, für root und den Operator, ob schon.
- `Exit node`: über welches Gerät der Internetverkehr dieses Geräts läuft, falls überhaupt. Siehe [Exit-Nodes]({{< relref "docs/exit-nodes" >}}).
- `Names`: die Domain, unter der dieses Gerät die anderen findet, etwa `home.juist`, oder der Grund, warum das nicht geht. Siehe [Namen]({{< relref "docs/names" >}}).
- `Freshness`: wann ein Voucher zuletzt bestätigt hat, dass dieses Gerät den aktuellen Stand des Netzes kennt, und wie lange das gilt. Ein Voucher ist ein Gerät, das diese Bestätigung im Auftrag des Netzes stündlich ausstellt. Nach 48 Stunden ohne Bestätigung steht dort `expired; vouchers only`; einen Tag vorher sagt eine Warnung, wann. Wo kein Gerät Voucher ist, steht dort `unchecked: no voucher`, und wo zwei Geräte Verkehr weiterleiten dürfen, schlägt ein Hinweis sie als Voucher vor. Siehe [Geräte entfernen]({{< relref "docs/remove" >}}).
- `Published`: die auf diesem Gerät veröffentlichten Namen, die es bedient,
  oder warum nicht. Siehe [Dienste veröffentlichen]({{< relref "docs/publishing" >}}).
- `Ingress`: auf einer Ingress, ob sie läuft, welche Namen sie bedient,
  welche Ports sie per TCP weiterreicht und welche ein anderes Programm
  belegt.
- `Sharing`: wie viele Freigaben dieses Gerät hält, die `juist share`
  auflistet, oder warum sie niemand erreicht.
- `Ports`: die Ports, auf denen juistd lauscht. `udp/41643` ist der für die Tunnel.
- `Updated`: wann juistd zuletzt einen neuen Stand des Netzes übernommen hat.

Zeilen wie `Subnets`, `Published` oder `Renumbering` erscheinen nur, wenn
die jeweilige Funktion genutzt wird.

## Die Geräte auflisten

`juist devices` listet alle Geräte in einer Tabelle auf:

```console
$ juist devices
NAME                  IPV4         REACHED  ROLES
laptop (this device)  198.18.36.1  -        -
nas                   198.18.36.2  direct   voucher, names, publishes
vps                   198.18.36.3  direct   voucher, relay
phone                 198.18.36.4  relayed  -
```

`ROLES` zeigt, welche Rollen das Netz einem Gerät gegeben hat, etwa
`voucher`, `relay` oder `exit`, dazu seine Subnetze, `names`, wenn
öffentliche Namen auf es zeigen, die [`juist names`]({{< relref "docs/names" >}})
auflistet, `publishes`, wenn es Namen veröffentlicht, die
[`juist publish`]({{< relref "docs/publishing" >}}) auflistet, und `-`, wenn es nichts davon hat. In einem schmalen Terminal
brechen die Rollen unter ihrer Spalte um, in einem noch schmaleren, etwa auf
dem Handy, bekommt jedes Gerät ein paar eigene Zeilen. `REACHED` gibt an, wie juistd das
Gerät bei der letzten Prüfung erreicht hat:

| `REACHED` | Bedeutung |
|---|---|
| `direct` | ein direkter Tunnel funktioniert |
| `relayed` | der Tunnel läuft über ein Relay |
| `no answer` | das Gerät hat nicht geantwortet, weil es offline ist oder eine Firewall es blockiert |
| `offline`, `offline, heard 3h ago` | das Gerät ist wahrscheinlich offline und hat sich seitdem nicht gemeldet |
| `not heard from` | das Gerät hat noch nicht mitgeteilt, wo es erreichbar ist |
| `not checked yet` | juistd hat noch nicht nachgesehen |
| `not connected` | das Gerät hat sich gemeldet, aber es gibt keinen Tunnel, etwa weil der Stand dieses Geräts veraltet ist |
| `-` | dieses Gerät selbst |

Unter [Zugriffsregeln]({{< relref "docs/access" >}}) zeigt `juist devices`
dieses Gerät und die Mitglieder, zu denen es einen Tunnel hat, und endet mit
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

`juist log show` sagt, was eine einzelne Änderung bewirkt hat, und welche
Schlüssel sie signiert haben. Du gibst sie mit ihrer Nummer oder dem Anfang
ihres Hashes an:

```console
$ juist log show 3
   3  change of a device's roles or subnets: vps
      gives vps (nid:QH4T7MWD…) the role relay
      approved by alice, with nid:Kc3vR8dE…
      hash MMOPGHJRKJ7DTZ2QWLQ6N5LXGZ4VQ3RJ4M2B7ZPXS2YQFG6C5WDA
```

Jede Änderung wird gegen das Netz beschrieben, wie es direkt davor war;
eine Änderung der Zugriffsregeln erscheint deshalb als Diff. Eine Uhrzeit
enthält das Log nicht, denn keine Änderung trägt ein signiertes Datum.
`juist log verify` prüft das gesamte Log noch einmal.

## Das Log des Daemons

```sh
journalctl -u juistd
```

Hier steht, was juistd selbst meldet. Ein zweites Netz auf demselben Gerät
hat einen eigenen Daemon, `juistd@juist1`, mit eigenem Log.

## Gut zu wissen

- Jeder lokale Benutzer darf `juist status` ausführen. Wer weder root noch
  [Operator]({{< relref "docs/operator" >}}) des Geräts ist, sieht die Ausgabe
  mit einem Hinweis `read-only` darunter.
- `juist devices`, `juist log` und alle anderen Befehle sind root und dem Operator vorbehalten.
- Ist ein Gerät in [mehreren Netzen]({{< relref "docs/networks" >}}), zeigen
  `juist status` und `juist devices` alle Netze nacheinander.
  `juist devices work` zeigt nur eines.

## Wenn etwas nicht klappt

`juist status` gibt Warnungen unter den Einzelheiten aus, jeweils mit einer Zeile
`hint:` darunter. Die häufigsten und was du dagegen tun kannst, stehen unter
[Fehlersuche]({{< relref "docs/troubleshooting" >}}).

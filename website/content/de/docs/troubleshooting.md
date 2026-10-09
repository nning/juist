---
title: Fehlersuche
linkTitle: Fehlersuche
description: Was juist status meldet, wenn etwas nicht stimmt, was das bedeutet und mit welchem Befehl du es behebst.
lead: Funktioniert etwas nicht, führe zuerst juist status aus. Der Befehl zeigt, worum du dich kümmern musst, und gibt einen Hinweis zur Lösung aus. Hier findest du die häufigsten Fälle.
---

## Wo du nachsiehst

Führe auf dem Gerät, das das Problem hat, Folgendes aus:

```sh
juist status
```

Warnungen beginnen mit `warning:` und stehen unter der Gerätetabelle. Auf jede
folgt eine Zeile `hint:` mit dem Befehl, der weiterhilft. Jeder lokale
Benutzer darf `juist status` ausführen. Was die einzelnen Zeilen bedeuten,
steht unter [Status und Geräte]({{< relref "docs/status" >}}).

Weitere Einzelheiten stehen im Log des Daemons:

```sh
journalctl -u juistd
```

Ein zweites Netz auf demselben Gerät hat einen eigenen Daemon mit eigenem
Log: `journalctl -u juistd@juist1`.

## Häufige Probleme

### `juistd not running`

Der Daemon, also das Programm, das die Tunnel aufrecht hält, läuft nicht.
Starte ihn:

```sh
sudo systemctl enable --now juistd
```

Für ein zweites Netz auf dem Gerät heißt der Daemon `juistd@juist1`. Unter
FreeBSD startest du ihn mit `service juistd start`. Siehe
[Installation]({{< relref "docs/install" >}}).

### `read-only; to manage this device …`

Du bist weder root noch der Operator des Geräts, also der lokale Benutzer,
der es ohne sudo verwalten darf. Du siehst nur den Status. Mach dich einmalig
zum Operator:

```sh
sudo juist set --operator=$USER
```

Siehe [Ohne sudo verwalten]({{< relref "docs/operator" >}}).

### `no answer from nas: offline, or udp/41643 blocked`

Das Gerät `nas` hat nicht geantwortet. Entweder ist es aus oder offline, oder
eine vorgeschaltete Firewall sperrt Port 41643/udp. Prüfe, ob es läuft. Hat
es eine öffentliche Adresse, öffne dort 41643/udp. Siehe
[Relays]({{< relref "docs/relays" >}}).

### `no tunnel traffic from nas`

`nas` ist bekannt, aber von dort kommt kein Verkehr an. Entweder ist Port
41643/udp gesperrt, oder beide Geräte stehen hinter NAT und es gibt kein
Relay, also kein Mitglied, das Verkehr zwischen Geräten weiterleitet, die
sich nicht direkt erreichen. Öffne 41643/udp auf einem Gerät mit öffentlicher
Adresse, wie der Hinweis vorschlägt:

```console
hint: on a device with a public address: sudo ufw allow juist, or firewall-cmd --add-service=juist
```

Oder mach ein solches Gerät mit `juist grant vps relay` zum Relay. Siehe
[Relays]({{< relref "docs/relays" >}}).

### `no device reaches this relay`

Dieses Gerät ist ein Relay, aber kein anderes Gerät kommt bei ihm an.
Wahrscheinlich ist Port 41645 für TCP oder UDP geschlossen. Öffne beide auf
dem Relay und in jeder vorgeschalteten Firewall, etwa der deines
Hosting-Anbieters:

```sh {device="vps"}
sudo ufw allow juist-relay
```

Mit firewalld: `sudo firewall-cmd --permanent --add-service=juist-relay && sudo firewall-cmd --reload`.
Siehe [Relays]({{< relref "docs/relays" >}}).

### `log sync to nas fails in the tunnel`

Der Tunnel steht, aber eine Firewall auf diesem Rechner verwirft den
Log-Abgleich, der darin läuft, also TCP 41644 auf `juist0`. Das Gerät
verpasst dann Änderungen am Netz, auch das Entfernen von Geräten. Lass
`juist0` auf beiden Geräten durch, wie der Hinweis vorschlägt:

```console
hint: on both devices: sudo ufw allow in on juist0, or add juist0 to firewalld's trusted zone
```

Liegt es an firewalld, meldet `juist status` `firewalld blocks juist0` und
nennt den passenden Befehl. Siehe [Relays]({{< relref "docs/relays" >}}).

### `no device may relay`

In einem Netz mit mehr als zwei Geräten darf kein Gerät Verkehr
weiterleiten. Geräte hinter strengen NATs brauchen aber ein Relay. Gib auf
dem Gerät eines Admins einem Gerät mit öffentlicher Adresse die Rolle:

```sh
juist grant vps relay
```

Siehe [Relays]({{< relref "docs/relays" >}}).

### `warning: no relay on 443/tcp`

Dieses Gerät sendet nur HTTPS, und kein Relay bedient einen öffentlichen
Namen auf 443, den einzigen Weg, auf dem es die anderen erreicht. Gib einem
Relay einen Namen, auf dem Relay:

```sh
sudo juist set --relay-name relay.example.org
```

Oder, in einem Netz, das mehr hinauslässt, `sudo juist set --https-only=false`.
Siehe [Nur HTTPS]({{< relref "docs/https-only" >}}).

### `Freshness  expired; vouchers only`

48 Stunden lang waren zu wenige Voucher erreichbar. Ein Voucher ist ein
Gerät, das stündlich bestätigt, dass der Stand des Netzes aktuell ist. Bis
wieder genug bestätigen, hält dieses Gerät nur Tunnel zu Vouchern, und sein
Zustand lautet `limited`. Bring einen Voucher wieder online. Damit es nicht
wieder passiert, mach nur Geräte zu Vouchern, die ständig laufen, und halte
einen in Reserve. Siehe [Geräte entfernen]({{< relref "docs/remove" >}}).

### `warning: freshness ends in 20h unless 2 vouchers vouch again`

Seit einem Tag haben weniger Voucher bestätigt als nötig. Nach der genannten
Zeit wird dieses Gerät wie oben `limited`. Bring vorher einen Voucher wieder
online.

### `removed`

Dieses Gerät gehört nicht mehr zum Netz. Willst du es weiter nutzen, tritt
mit einer neuen Einladung bei, oder fang von vorn an:

```sh
juist reset
```

Siehe [Geräte entfernen]({{< relref "docs/remove" >}}) und
[Einladungen]({{< relref "docs/invites" >}}).

### `no IPv4 on this host`

Dieses Gerät ist in zwei Netzen, deren IPv4-Bereiche sich überschneiden. Das
zweite funktioniert dann nur über IPv6. Verschieb eines der beiden in einen
anderen Bereich, zum Beispiel:

```sh
juist network renumber work 10.7.0.0/24
```

Siehe [Mehrere Netze]({{< relref "docs/networks" >}}).

### `Exit node  vps, internet refused: …`

Dieses Gerät leitet seinen Internetverkehr über den Exit-Node `vps`, kann ihn
aber gerade nicht nutzen, etwa weil `vps` nicht erreichbar ist. juist blockiert
den Verkehr dann, statt ihn direkt zu verschicken. Mach `vps` wieder
erreichbar, oder geh wieder direkt ins Internet:

```sh
juist exit off
```

Siehe [Exit-Nodes]({{< relref "docs/exit-nodes" >}}).

### `this device does not serve: IP forwarding is off …`

Dieses Gerät soll ein Exit-Node sein, aber der Rechner leitet keinen Verkehr
weiter. Führe dort noch einmal folgenden Befehl aus, er richtet den Rechner
mit sudo ein:

```sh
juist exit serve
```

Siehe [Exit-Nodes]({{< relref "docs/exit-nodes" >}}).

### `DNS goes to …, outside the tunnel: systemd-resolved refused juistd …`

Du nutzt einen Exit-Node, aber systemd-resolved hat juistd nicht erlaubt,
DNS durch den Tunnel zu leiten. Die Anfragen gehen also direkt ins Internet.
Das juist-Paket bringt eine polkit-Regel mit, die juistd das erlaubt, wo
polkit läuft. Installiere juist deshalb als Paket, und polkit, wo es dem Host
fehlt. Siehe
[Installation]({{< relref "docs/install" >}}) und
[Namen]({{< relref "docs/names" >}}).

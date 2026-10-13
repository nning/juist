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

Warnungen beginnen mit `warning:` und stehen unter den Einzelheiten. Auf jede
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
der es ohne sudo verwalten darf. Du siehst den Status, mehr nicht. Mach dich
einmalig zum Operator:

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
Wahrscheinlich ist Port 41645 für TCP oder UDP geschlossen. Öffne ihn für
beide auf dem Relay und in jeder vorgeschalteten Firewall, etwa der deines
Hosting-Anbieters:

```sh {device="vps"}
sudo ufw allow juist-relay
```

Mit firewalld: `sudo firewall-cmd --permanent --add-service=juist-relay && sudo firewall-cmd --reload`.
Siehe [Relays]({{< relref "docs/relays" >}}).

### `log sync to nas fails in the tunnel`

Der Tunnel steht, aber eine Firewall auf diesem Rechner verwirft den
Log-Abgleich, der darin läuft (TCP 41644 auf `juist0`). Das Gerät verpasst
dann Änderungen am Netz, auch das Entfernen von Geräten. Lass eingehenden
Verkehr auf `juist0` auf beiden Geräten durch, wie der Hinweis vorschlägt:

```console
hint: on both devices: sudo ufw allow in on juist0, or add juist0 to firewalld's trusted zone
```

Liegt es an firewalld, meldet `juist status` `firewalld blocks juist0` und
nennt den passenden Befehl. Siehe [Relays]({{< relref "docs/relays" >}}).

### `warning: log sync fails: nas runs a newer juist`

Auf nas läuft eine neuere Version von juist, deren Änderungen diese nicht
lesen kann. Bis du juist auf diesem Gerät aktualisierst, verpasst es
Änderungen am Netz.

### `warning: log sync to nas fails`

Der Tunnel steht und der Log-Abgleich erreicht nas, scheitert aber. Warum,
steht im Log von juistd.

### `no device may relay`

Das Netz hat mehr als zwei Geräte, aber keines davon darf Verkehr
weiterleiten. Geräte hinter strengen NATs brauchen ein Relay. Gib auf dem
Gerät eines Admins einem Gerät mit öffentlicher Adresse die Rolle:

```sh
juist grant vps relay
```

Siehe [Relays]({{< relref "docs/relays" >}}).

### `warning: no relay on 443/tcp`

Dieses Gerät sendet nur HTTPS und erreicht die anderen deshalb nur über ein
Relay, das einen öffentlichen Namen auf Port 443 bedient. Ein solches gibt es
nicht. Gib einem Relay einen öffentlichen Namen, indem du auf dem Relay
Folgendes ausführst:

```sh
sudo juist set --relay-name relay.example.org
```

Lässt das Netz mehr als HTTPS hinaus, genügt auch
`sudo juist set --https-only=false`. Siehe
[Nur HTTPS]({{< relref "docs/https-only" >}}). Hat ein Relay einen Namen und
die Warnung bleibt, gibt sich der Server unter diesem Namen nicht als dieses
Relay zu erkennen. Prüfe das DNS des Namens.

### `warning: juistd may bind any port below 1024, which no relay on 443 here needs`

juistd durfte Port 443 belegen, damit ein Relay seinen öffentlichen Namen
bedienen kann. Der Name ist weg, das Recht aber geblieben, etwa weil der Name
ohne root entfernt wurde und das Recht deshalb nicht entzogen werden konnte.
Entzieh es, wie der Hinweis sagt:

```sh
sudo /usr/lib/juist/relay.sh off
```

Auch `juist reset` entzieht es. Siehe [Relays]({{< relref "docs/relays" >}}).

### `Freshness  expired; vouchers only`

48 Stunden lang waren zu wenige Voucher erreichbar. Ein Voucher ist ein
Gerät, das stündlich bestätigt, dass der Stand des Netzes aktuell ist. Bis
wieder genug bestätigen, hält dieses Gerät nur Tunnel zu Vouchern, und sein
Zustand lautet `limited`. Bring einen Voucher wieder online. Damit es nicht
wieder passiert, mach nur Geräte zu Vouchern, die ständig laufen, und nimm
einen mehr, als du brauchst. Siehe [Geräte entfernen]({{< relref "docs/remove" >}}).

### `warning: freshness ends in 20h unless 2 vouchers vouch again`

Seit einem Tag haben weniger Voucher bestätigt als nötig. Ist die genannte
Zeit abgelaufen, wird dieses Gerät wie oben beschrieben `limited`. Bring vorher einen Voucher wieder
online.

### `warning: nas runs an older juist, unreachable until updated`

Das Netz wurde aktualisiert, und auf nas läuft noch eine Version von juist
von vor dem Upgrade. Bis du juist auf nas aktualisierst, erreicht nichts von
deinem Verkehr nas, und nichts von seinem dich. Sein Tunnel trägt nur die
Änderungen am Netz, damit nas dir dasselbe melden kann. `juist devices` zeigt
es als `outdated`. Hat nas gar keinen Tunnel zu diesem Gerät, weil seine
Version kein Gerät kennt, das nach dem Upgrade beigetreten ist, zeigt es
`no answer`.

### `warning: nas runs an older juist, which applies no changes until updated`

Das Netz wurde aktualisiert, und auf nas läuft noch eine Version von juist
von vor dem Upgrade. nas bleibt erreichbar, übernimmt aber keine Änderung am
Netz, bis du juist auf nas aktualisierst, auch kein Entfernen.
`juist status` auf nas meldet dasselbe.

### `warning: nas fell too far behind to reach this device`

nas war für mehr Änderungen offline, als dieses Gerät Schlüssel aufbewahrt.
nas kann den Stand von einem Gerät nachholen, das diese Schlüssel noch hat,
meist von einem, das ebenso lange offline war. Sonst nimm nas mit einer neuen
Einladung wieder ins Netz auf. Das wird nur über ein Gerät gesagt, das läuft:
Von einem, das offline ist, hat dieses Gerät womöglich nur eine Ankündigung
von vor seinem eigenen Beitritt.

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
weiter. Führe dort noch einmal folgenden Befehl aus. Er richtet den Rechner
mit sudo ein:

```sh
juist exit serve
```

Siehe [Exit-Nodes]({{< relref "docs/exit-nodes" >}}).

### `DNS goes to …, outside the tunnel: systemd-resolved refused juistd …`

Du nutzt einen Exit-Node, aber systemd-resolved hat juistd nicht erlaubt,
DNS durch den Tunnel zu leiten. Die Anfragen gehen also direkt ins Internet.
Das juist-Paket bringt eine polkit-Regel mit, die juistd das erlaubt, sofern
polkit läuft. Installiere juist deshalb als Paket, und polkit, wo die Zeile
auf `polkit is not installed` endet, wie der Hinweis sagt. Siehe
[Installation]({{< relref "docs/install" >}}) und
[Namen]({{< relref "docs/names" >}}).

---
title: Schlüssel erneuern und zurücksetzen
linkTitle: Schlüssel
description: Einem Gerät neue Schlüssel geben, ein Gerät von vorn beginnen lassen, mit einem verlorenen Gerät umgehen, Admin-Schlüssel sichern und wissen, was sich nicht rückgängig machen lässt.
lead: Jedes Gerät hat eigene Schlüssel, und alle Geräte eines Netzes teilen ein gemeinsames Geheimnis. Du kannst beides ersetzen, ein Gerät aus dem Netz nehmen und von vorn beginnen lassen oder ein verlorenes Gerät aussperren.
---

## Welche Schlüssel es gibt

Jedes Gerät hat eigene Schlüssel. Seine WireGuard- und Sealing-Schlüssel
schützen seine Tunnel und die Nachrichten, die an es versiegelt werden. Sein
Identitätsschlüssel weist es im Mitgliederlog aus, der signierten Liste
aller Änderungen, die jedes Gerät prüft
([So funktioniert juist]({{< relref "docs/how-it-works" >}})).

Außerdem hat das Netz ein Gruppengeheimnis, das alle Mitglieder kennen und
mit dem sie einander finden. Admin-Schlüssel sind noch einmal etwas anderes:
Sie gehören Personen und dienen dazu, Änderungen zu bestätigen
([Mehrere Admins]({{< relref "docs/admins" >}})).

Einen Schlüssel zu ersetzen heißt, ihn zu erneuern. Ein neuer Schlüssel ist
eine Änderung am Log, die Admins bestätigen ihn also wie jede andere
Änderung.

## Schlüssel erneuern

| Was du ersetzen willst | Befehl | Hinweis |
|---|---|---|
| die WireGuard- und Sealing-Schlüssel dieses Geräts | `juist rotate` | Name und Adressen bleiben gleich |
| den Identitätsschlüssel dieses Geräts | `juist rotate identity` | die IPv6-Adresse ändert sich |
| das Gruppengeheimnis des Netzes | `juist rotate group-secret` | nach einem Leck |

Mit `juist rotate` gibst du einem Gerät, dem du noch vertraust, neue
Schlüssel. Liegt auf dem Gerät ein Admin-Schlüssel des Netzes und reicht dem
Quorum eine Stimme, gilt die Änderung sofort:

```console {device="laptop"}
$ juist rotate
new keys cfe695661243
new keys live
rotated this device's keys
```

Braucht die Änderung einen weiteren Admin, wartet sie auf dessen Bestätigung,
und die neuen Schlüssel bleiben vorgemerkt, bis das Log sie enthält. Mit
`juist rotate abandon` verwirfst du eine Erneuerung, die noch auf
Bestätigung wartet.

Verbindungen laufen weiter, während das Gerät auf seine neuen Schlüssel
wechselt: Der Tunnel zu jedem Gerät wartet kurz auf einen Handshake mit den
neuen Schlüsseln. Ein Gerät, das ein Relay betreibt, startet seine Tunnel
stattdessen neu. `juist rotate identity` ändert die IPv6-Adresse des Geräts
und beendet damit alle Verbindungen über die alte. Dafür muss das Netz auf
Schema 19 stehen: Darunter bricht er mit
`juist: the network predates rotating an identity key` ab, bis ein Admin
`juist log upgrade` ausführt ([juist aktualisieren]({{< relref "docs/updating" >}})).

## Ein Gerät von vorn beginnen lassen

Mit `juist reset` verlässt ein Gerät das Netz und ist danach wie frisch
installiert. Es vergisst das Netz und alles, was es dafür gespeichert hatte:
Schlüssel, Log, Peers und Operator. Admin-Schlüssel bleiben erhalten. Im
folgenden Beispiel war `phone` schon aus dem Netz entfernt:

```console {device="phone"}
$ juist reset
forget "home" and reset this device, with new keys? [y/N] y
reset; new keys, no network
```

Liegen Admin-Schlüssel in deinem Keystore, kommt noch die Zeile
`admin keys kept in ~/.config/juist/admins` mit dem vollständigen Pfad hinzu.

Führt das Netz das Gerät noch als Mitglied, braucht `juist reset` die Option
`--force`. Entferne das Gerät nach Möglichkeit vorher vom Gerät eines Admins
aus, damit auch die anderen Geräte ihm nicht mehr vertrauen.

Ist ein Gerät in [mehreren Netzen]({{< relref "docs/networks" >}}), vergisst
es nur das angegebene Netz: `juist reset work --force`. Dessen juistd wird
dabei mit entfernt, außer es ist das erste Netz. Die anderen Netze behalten
ihre Schlüssel.

## Wenn ein Gerät verloren ist

{{< step on="dem Gerät eines Admins" >}}
Entferne das verlorene Gerät:

```sh
juist remove phone
```

Dabei wird auch das Gruppengeheimnis erneuert. Jedes Gerät baut seinen Tunnel
zu phone ab, sobald es davon erfährt. Ein Gerät, das vom Rest abgeschnitten
ist, tut das spätestens, wenn seine Frische abläuft, also nach 48 Stunden
ohne Voucher.
{{< /step >}}

{{< step on="dem Gerät eines Admins" >}}
Lag auf dem verlorenen Gerät ein Admin-Schlüssel, entzieh diesem Schlüssel
auch seine Stimme. In der Spalte `ON` von `juist admins` siehst du, welcher
Schlüssel dort lag:

```sh
juist admins remove nid:…
```

juist lehnt das ab, wenn die übrigen Schlüssel das Quorum nicht erreichen.
{{< /step >}}

Ein Ersatzgerät tritt wie jedes neue Gerät mit einer neuen Einladung bei
([Einladungen]({{< relref "docs/invites" >}})). Taucht das alte Gerät wieder
auf, meldet sein `juist status` den Zustand `removed`. Lade es dann neu ein,
oder führe dort `juist reset` aus.

## Admin-Schlüssel sichern

Ein Admin-Schlüssel liegt nur im Schlüsselspeicher des Rechners, auf dem er
entstanden ist. Für eine Kopie im Passwortmanager gibst du ihn als eine Zeile
aus und leitest sie dorthin. `juist admins` listet die Schlüssel auf diesem
Rechner unter `KEY HERE`:

{{< step on="dem Rechner eines Admins" >}}
```sh
juist admins export alice@home | pass insert -m juist/alice
```
{{< /step >}}

Zurück bekommst du ihn auf jedem Rechner, indem du die Zeile wieder
hineinleitest:

```console {device="laptop"}
$ pass show juist/alice | juist admins import alice@home
imported admin key "alice@home"
it casts 1 vote in "home"
```

Die Zeile läuft immer durch eine Pipe, nie über die Kommandozeile. Sie trägt
eine Prüfsumme, deshalb wird eine abgeschnittene Zeile abgelehnt. Sie deckt
auch den quantensicheren Signaturschlüssel ab, der sich aus ihr ableitet. Ein
Import ersetzt nie einen vorhandenen Schlüssel. Wurde der Schlüssel seit der
Sicherung aus dem Netz entfernt, warnt der Import mit
`"home" gives it no vote`.

Die Break-glass-Zeile, die `juist create` angezeigt hat, bewahrst du ebenso
auf, aber getrennt von den Admin-Schlüsseln
([Das Netz beenden]({{< relref "docs/network-changes" >}}#das-netz-beenden)).

Die eigenen Schlüssel eines Geräts lassen sich nicht exportieren: Eine Kopie
auf einem anderen Rechner wäre ein zweites Gerät unter dem Namen des ersten.
Entferne ein verlorenes Gerät stattdessen und lade ein neues ein.

## Hinweise

- Erneuern, Zurücksetzen und Entfernen dürfen nur root und der
  [Operator]({{< relref "docs/operator" >}}) des Geräts. Zum Bestätigen
  braucht es einen Admin-Schlüssel.
- `juist reset` warnt, wenn das Gerät das einzige im Netz ist, denn dann
  verschwindet das Netz mit ihm.
- `juist log` zeigt jede Erneuerung und wer sie bestätigt hat.

{{< note danger >}}
Gehen so viele Admin-Schlüssel verloren, dass kein Quorum mehr zustande kommt,
ist das endgültig. Bleiben weniger Admin-Schlüssel übrig, als eine Änderung
braucht, lässt sich keine Änderung mehr signieren: Kein Gerät kann mehr
hinzukommen oder entfernt werden. Das Break-glass-Geheimnis, das
`juist create` anzeigt, gibt dem Netz keine neuen Admins, es beendet es
endgültig ([Das Netz beenden]({{< relref "docs/network-changes" >}}#das-netz-beenden)).
Vorbeugen kannst du so: Sichere jeden Admin-Schlüssel, setze mehr Admins ein,
als das Quorum braucht, jeden mit eigenen Geräten, und halte bei
`juist admins require` einen Schlüssel mehr bereit, als verlangt wird.
{{< /note >}}

Warum juist das in Kauf nimmt, steht unter
[Trade-offs]({{< home "trade-offs" >}}).

## Fehlersuche


| Was du siehst | Was du tun kannst |
|---|---|
| `juist: still a member of "home"` | Entferne das Gerät zuerst mit `juist remove phone` auf dem Gerät eines Admins, oder häng `--force` an. |
| `juist status`: `removed` | Dieses Gerät gehört nicht mehr zum Netz. Tritt mit einer neuen Einladung wieder bei, oder führe `juist reset` aus. |
| `hint: the new keys stay staged until the log names them or: juist rotate abandon` | Warte auf die Bestätigung, oder verwirf die Erneuerung mit `juist rotate abandon`. |
| `juist: no admin key of this network in …` | Führe den Befehl dort aus, wo der Schlüssel eines Admins liegt. |

---
title: juist aktualisieren
linkTitle: juist aktualisieren
description: Eine neue Version auf jedem Gerät installieren und das Netz auf ein neues Schema heben, sobald alle sie haben.
lead: Um juist zu aktualisieren, installierst du das Paket der neuen Version auf jedem Gerät. Manche Versionen bringen außerdem ein neues Format für das Log des Netzes mit. Darauf wechselt das Netz erst, wenn ein Admin juist log upgrade ausführt, nachdem jedes Gerät die neue Version hat.
---

## Eine neue Version installieren

Das neue Paket installierst du genauso wie das erste
([Installieren]({{< relref "docs/install" >}})). Schlüssel, Netze und
Einstellungen des Geräts bleiben erhalten.

{{< step on="einem Gerät mit Debian oder Ubuntu" >}}
```sh
curl -LO https://github.com/nning/juist/releases/latest/download/juist_amd64.deb
sudo apt install ./juist_amd64.deb
```

Das Paket startet juistd neu, und `juist-ingress` und `juist-serve`, wo sie
laufen. Unter Fedora macht `sudo dnf install` mit dem neuen RPM dasselbe.
{{< /step >}}
{{< step on="einem Gerät mit FreeBSD" >}}
Installiere das Paket als root und starte den Daemon danach selbst neu, weil
pkg das nicht kann:

```sh
pkg add https://github.com/nning/juist/releases/latest/download/juist-freebsd15-amd64.pkg
service juistd restart
```

Das startet die Daemons aller Netze auf dem Gerät neu. Wo sie laufen,
startest du auch `juist_ingress` und `juist_serve` neu. Bis dahin laufen die
alten Daemons weiter.
{{< /step >}}

Geräte mit unterschiedlichen Versionen arbeiten weiter zusammen, solange das
Netz auf seinem Schema bleibt. Du kannst sie also eins nach dem anderen
aktualisieren. Auf einem
Telefon installierst du die neue APK über die alte
([Android]({{< relref "docs/android" >}}#die-app-installieren)).

## Das Schema

Jedes Gerät prüft jede Änderung im Log des Netzes, also müssen alle das
Format verstehen, in dem die Änderungen geschrieben sind. Dieses Format ist
das **Schema**, und es hat eine Nummer, etwa 20 oder 21. Jede Version von
juist beherrscht ein Schema und liest die älteren bis hinunter zu 18.

Eine neue Version ändert das Schema des Netzes nicht von selbst. Das Netz
bleibt bei seinem Schema, bis ein Admin es anhebt. Ein Gerät, das noch nicht
aktualisiert ist, arbeitet deshalb weiter.

Beherrscht die Version auf diesem Gerät ein neueres Schema als das Netz,

- zeigt die Zeile `Schema` von `juist status` das Schema des Netzes und in
  Klammern das dieser Version, etwa `20 (21)`;
- ergänzt `juist health` auf einem Gerät mit Admin-Schlüssel, sobald das
  juist jedes Geräts es beherrscht,
  `hint: every device implements schema 21: juist log upgrade`.

## Das Schema anheben

{{< step on="einem beliebigen Gerät" >}}
Prüfe, ob jedes Gerät die neue Version hat. Die Spalte `SCHEMA` von
`juist devices` zeigt das neueste Schema, das das juist jedes Geräts
beherrscht, gelb, wo es älter ist als das dieses Geräts:

```console
$ juist devices
NAME                  IPV4         REACHED  SCHEMA  ROLES
laptop (this device)  198.18.36.1  -        21      -
nas                   198.18.36.2  direct   21      voucher
phone                 198.18.36.4  relayed  20      -
```

Hier braucht das Telefon noch die neue App. Ein `-` statt einer Nummer
heißt, dass juistd von diesem Gerät noch nichts gehört hat: Es war seit dem
Beitritt aus, oder seine Mitgliedschaft ist abgelaufen.
{{< /step >}}
{{< step on="dem Gerät eines Admins" >}}
Hebe das Schema des Netzes an:

```console
$ juist log upgrade
warning: raising schema 20 to schema 21, which cannot be undone
continue? [y/N] y
upgraded to schema 21
```

Solange das juist eines Geräts das neue Schema nicht beherrscht oder juistd
von ihm nichts gehört hat, ändert `juist log upgrade` nichts und nennt es:

```console
$ juist log upgrade
juist: not every device implements schema 21: phone (20)
hint: update them, or raise it anyway: juist log upgrade --force
```

Mit `--force` hebt es das Schema trotzdem an, und die genannten Geräte stehen
still, bis sie aktualisiert sind. Welches Schema jedes Gerät beherrscht,
erfährt juist von juistd. Führe den Befehl deshalb auf einem Gerät des Netzes
aus, auf dem juistd läuft.

Wie jede Änderung braucht die Anhebung die Stimmen des Quorums; ist es
größer als eins, wartet sie auf die anderen Admins
([Mehrere Admins]({{< relref "docs/admins" >}})).
{{< /step >}}

## Von selbst anheben

`juist log upgrade --when-ready` hebt das Schema ohne Rückfrage an, sobald
jedes Gerät es beherrscht, und tut und sagt bis dahin nichts; auf welche
Geräte es wartet, sagt `juist log upgrade`.

{{< step on="dem Gerät eines Admins" >}}
Lass es regelmäßig laufen, als der Benutzer, in dessen Keystore der
Admin-Schlüssel liegt, etwa täglich aus seiner crontab (`crontab -e`):

```
0 3 * * * juist log upgrade --when-ready
```

Ist das Quorum größer als eins, reicht deine Stimme allein nicht:
`--when-ready` schlägt dann nichts vor und scheitert, und du führst
`juist log upgrade` selbst aus.
{{< /step >}}

## Ein Gerät, das die Aktualisierung verpasst hat

Ein Gerät, dessen juist das neue Schema des Netzes nicht kennt, wendet keine
Änderungen mehr an, auch kein Entfernen, bis es aktualisiert ist. Die anderen
Geräte warnen in `juist health` davor:

```console
warning: nas runs an older juist, which applies no changes until updated
```

Ein Gerät mit älterer Version kann auch ganz vom Verkehr abgeschnitten sein:
Die anderen schicken ihm nur noch die Änderungen am Netz. `juist devices`
zeigt es als `outdated`, und `juist health` meldet
`nas runs an older juist, unreachable until updated`.

In beiden Fällen installierst du auf dem Gerät die neue Version. Es holt das
Log dann von selbst nach. Die Android-App folgt dem Netz ebenso erst wieder,
wenn sie aktualisiert ist.

## Gut zu wissen

- juist liest Netze, deren Log mindestens auf Schema 18 steht, in denen
  jede Änderung quantensicher signiert ist
  ([Sicherheit]({{< relref "docs/security" >}}#quantensicher)). Ein Netz, das
  mit einem älteren juist angelegt wurde, lässt sich nicht mehr lesen: Seine
  Admins legen es neu an, und seine Geräte treten dem neuen bei.
- `juist log` führt die Anhebung als `schema upgrade`, mit den Admins, die
  sie bestätigt haben. Rückgängig machen lässt sie sich nicht.
- Eine Einladung zwischen zwei Geräten, deren Versionen sich nicht verstehen,
  scheitert mit `the inviting device runs an incompatible version of juist`.
  Aktualisiere beide und lade dann erneut ein.
- `juist version` zeigt, welches Release auf diesem Gerät läuft, etwa
  `v0.23.0`; ein Build zwischen zwei Releases zeigt das nächste und seinen
  Commit, etwa `v0.23.1-0.20261024075157-M23`. „Über juist“ in der
  App zeigt dasselbe ohne `v`.

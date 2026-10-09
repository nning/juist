---
title: Mehrere Admins
linkTitle: Mehrere Admins
description: Admins und Admin-Schlüssel hinzufügen, festlegen, wie viele eine Änderung bestätigen müssen, und Änderungen bestätigen, die auf dich warten.
lead: Ein Admin ist eine Person, deren Schlüssel Änderungen am Netz bestätigt. Mit mehreren Admins legst du fest, wie viele zustimmen müssen, bevor ein Gerät beitritt, das Netz verlässt oder eine Rolle bekommt.
---

## Worum es geht

Jede Änderung am Netz ist ein Eintrag im Mitgliederlog, egal ob ein Gerät
aufgenommen, entfernt oder mit einer Rolle versehen wird. Das Log ist die
signierte Liste aller Änderungen, und jedes Gerät prüft sie selbst
([So funktioniert juist]({{< relref "docs/how-it-works" >}})). Eine Änderung
gilt, sobald genug Admins sie signiert haben.

Ein **Admin** ist eine Person. Ein **Admin-Schlüssel** ist der Schlüssel, mit
dem diese Person signiert. Er liegt als Datei wie `admins/alice@home.key` in
ihrem Keystore `~/.config/juist`. Ein Admin hat auf jedem Gerät, von dem aus
er Änderungen bestätigt, einen eigenen Schlüssel. Kopiere nie einen Schlüssel
auf ein anderes Gerät, sondern leg dort einen neuen an.

Das **Quorum** ist die Zahl der Stimmen, die eine Änderung braucht. Jeder
Admin-Schlüssel hat eine Stimme. Die Schlüssel einer Person zählen aber
zusammen nur einmal, egal mit welchem sie signiert. Angenommen, alice, bob und
carol sind Admins mit je einer Stimme, und das Quorum ist 2. Dann reichen zwei
beliebige von ihnen, um eine Änderung zu bestätigen, und einer darf im Urlaub
sein. Allein kann niemand etwas ändern.

Ein Admin ist nicht dasselbe wie ein Voucher. Ein Voucher ist ein Gerät mit
der Rolle `voucher`, das stündlich bestätigt, dass der Stand des Netzes
aktuell ist. Einen Admin-Schlüssel hat ein Voucher nicht.

## Von zwei Laptops aus bestätigen

Deinen Admin-Namen findest du in der Ausgabe von `juist create` in der Zeile
`Admin`, und `juist admins` listet ihn auf. Es ist dein Login-Name, es sei
denn, du hast `--admin-name` angegeben. Verwende genau diesen Namen für den
Schlüssel des zweiten Laptops. Unter jedem anderen Namen würde der Schlüssel
zu einem zweiten Admin.

{{< step on="laptop2" as="deinem zweiten Laptop" >}}
Leg einen Schlüssel unter deinem Admin-Namen an:

```sh
juist admins new alice
```

Die Ausgabe enthält den Befehl, der den Schlüssel hinzufügt, mitsamt dem
Schlüssel.
{{< /step >}}

{{< step on="laptop" as="deinem ersten Laptop" >}}
Führe den Befehl genau so aus, wie er ausgegeben wurde:

```sh
juist admins add alice nid:… --on laptop2
```

Die Ausgabe lautet `added a key of alice's; 2 keys, 1 signing`.
{{< /step >}}

`juist admins` zeigt dann, auf welchem Rechner welcher Schlüssel liegt. Wartet
eine Änderung auf Bestätigung, erfährst du dort auch, wo die Schlüssel liegen,
die sie bestätigen können.

## Ein Schlüssel pro Netz

Jedes Netz bekommt einen eigenen Admin-Schlüssel, etwa
`admins/alice@home.key`. Geht ein Schlüssel verloren oder wird er gestohlen,
ist also nur ein Netz betroffen, und zwei Netze teilen sich nie einen
Schlüssel.

- Ein Schlüssel aus `juist admins new` wird unter dem ersten Netz abgelegt,
  in dessen Log er auftaucht. Mit `juist admins new alice --network home`
  legst du das Netz gleich fest.
- Soll ein neues Netz mit einem Schlüssel verwaltet werden, den du schon
  hast, gibst du ihn an: `juist create lab --admin-key alice@home`.
- `juist admins` listet die Schlüssel auf diesem Rechner auf und zu jedem die
  Netze, die er verwaltet.
- Auf einem Rechner, der zu keinem Netz gehört, legst du mit
  `juist approve --key alice@home FILE` fest, welcher Schlüssel signiert.

## Zwei Admins, keiner entscheidet allein

Angenommen, alice und bob haben je zwei Geräte, und jede Änderung soll die
Zustimmung von beiden brauchen.

{{< step on="dem Gerät eines Admins" >}}
Füge jeden von bobs Schlüsseln hinzu, einen pro Gerät. Bob legt sie mit
`juist admins new bob` an, das jeweils die passende Zeile ausgibt:

```sh
juist admins add bob nid:…
```

Bob hat jetzt zwei Schlüssel, die zusammen eine Stimme haben.
{{< /step >}}

{{< step on="dem Gerät eines Admins" >}}
Mach drei Geräte, die ständig laufen, zu Vouchern, verlange, dass zwei von
ihnen den Stand des Netzes bestätigen, und für jede Änderung beide Admins:

```sh
juist grant nas voucher
juist grant vps voucher
juist grant pi voucher
juist admins vouchers 2
juist admins quorum 2
```

`juist admins` zeigt jetzt `Quorum  2 of 2 votes`.
{{< /step >}}

Mit `juist admins vouchers 2` kann ein Voucher, der über den Stand des Netzes
lügt, kein Gerät mehr allein täuschen. Er bräuchte einen Komplizen. Dafür
müssen aber auch zwei Voucher online sein; der dritte sorgt dafür, wenn einer
ausfällt.

## Allein, aber mit zwei Geräten für jede Änderung

Auch als einziger Admin kannst du verlangen, dass jede Änderung von zwei
deiner Geräte bestätigt wird:

```sh
juist admins require alice 2
```

Halte dafür drei Schlüssel bereit. Mit genau zwei kann schon der Verlust
eines Geräts das Netz sperren.

## Wenn eine Änderung einen weiteren Admin braucht

Braucht eine Änderung die Stimme eines anderen Admins, wartet sie auf den
Voucher-Geräten des Netzes auf ihn. Das siehst du schon, wenn du die Änderung
anstößt:

```console {device="laptop"}
$ juist remove phone
remove phone (198.18.36.4  fd77:9359:d9fb:bcb6:5fc:cc5c:f45d:c475) from "home"? [y/N] y
pending remove-phone.rec: needs 1 more vote, from bob on nas; another admin runs, on an admin device or with the file:
  juist approve
  juist approve remove-phone.rec
```

Auf bobs Gerät meldet `juist status` dann `1 change waits for your vote: …`.
Bob bestätigt die Änderung dort:

```console {device="nas"}
$ juist approve
device removal, proposed by alice's key on laptop:
  removes the device phone (nid:A7Bu6lgr…)
approve? [y/N] y
signed as bob's key on nas
applied
```

`juist approve` fragt zu jeder Änderung nach, die auf deine Stimme wartet.
Was eine Änderung bewirkt, entnimmt es dem Eintrag und dem Log, nie dem
Dateinamen. Sobald eine Änderung genug Stimmen hat, gilt sie auf jedem Gerät.

Damit wartende Änderungen die Geräte eines Admins erreichen, führt jeder
Admin einmal `juist admins receive` aus. Wer ein Netz gegründet hat, hat das
bereits getan. Auch das ist eine Änderung wie jede andere.

## Änderungsdateien

Jede Änderung wird zusätzlich als Datei gespeichert, etwa
`remove-phone.rec`, und zwar in dem Verzeichnis, in dem du den Befehl
aufgerufen hast. Du kannst sie einem anderen Admin schicken, der auf einem
Gerät im Netz Folgendes aufruft:

```sh
juist approve remove-phone.rec
```

Der Befehl zeigt, was die Änderung bewirkt, fragt nach, signiert die Datei an
Ort und Stelle und wendet die Änderung an, sobald sie vollständig ist.
`juist apply` macht dasselbe.

Auf einem Rechner, der zu keinem Netz gehört, kann ein Admin die Aufnahme
eines Geräts bestätigen. Änderungen, die beeinflussen können, wer bestätigt
oder wer Voucher ist, kann er dort aber nicht bestätigen: kein Entfernen,
keine Rolle, keinen Admin-Schlüssel und kein Quorum. Wen eine solche Änderung
betrifft, verrät nämlich nur das Log.

## Gut zu wissen

- `juist admins` listet alle Admins mit ihren Stimmen auf, die Rechner, auf
  denen ihre Schlüssel liegen, das Quorum und die Zahl der nötigen Voucher.
- `juist admins add NAME KEY --votes N` gibt einem Schlüssel mehr als eine
  Stimme. `juist create --admin-votes N` macht dasselbe für den Schlüssel, den
  `juist create` anlegt.
- `juist admins remove NAME|KEY` entzieht einem Schlüssel seine Stimme. Das
  wird abgelehnt, wenn die übrigen Schlüssel das Quorum nicht mehr erreichen.
- `juist admins quorum` warnt, wenn jede Änderung alle Admins braucht, denn
  dann sperrt schon der Verlust der Schlüssel eines einzigen Admins das Netz.
  Ist das Quorum größer als 1 und hat das Netz keinen Voucher, weist es
  darauf hin, dass Änderungen, die auf Stimmen warten, über Voucher laufen;
  `juist create --quorum` ebenso.
- Admin-Schlüssel verlassen ihren Rechner nur als Sicherungszeile
  ([Schlüssel]({{< relref "docs/keys" >}}#admin-schlüssel-sichern)), und dieser
  Rechner muss selbst zu keinem Netz gehören. Mit `juist create --no-device` legst du ein Netz von
  einem Rechner aus an, der nur signiert.
- Führe Admin-Befehle als du selbst aus, ohne sudo, denn die Schlüssel liegen
  in deinem Keystore.
- `juist log` zeigt jede Änderung und wer sie bestätigt hat.
- [Zugriffsregeln]({{< relref "docs/access" >}}) änderst du genauso.
  `juist approve policy.rec` zeigt die Änderung als Diff gegen die geltenden
  Regeln.
- Nach einem Update von juist meldet `juist status` auf deinem Gerät
  `the network is at schema 9, this version at schema 10`, wenn diese Version
  dem Log des Netzes etwas hinzufügt. Sobald alle Geräte sie haben, führe
  `juist log upgrade` aus. Geräte mit älteren Versionen übernehmen ab dem
  Upgrade keine Änderungen mehr, bis sie aktualisiert sind.

{{< note danger >}}
Gehen so viele Admin-Schlüssel verloren, dass keine Änderung mehr genug
Stimmen bekommt, ist das Netz für immer gesperrt. Das Break-glass-Geheimnis,
das `juist create` anzeigt, kann es nur beenden
([Das Netz beenden]({{< relref "docs/network-changes" >}}#das-netz-beenden)).
Sichere jeden Admin-Schlüssel, und setze mehr Admins ein, als das Quorum
braucht, jeden mit eigenen Geräten
([Schlüssel]({{< relref "docs/keys" >}}#admin-schlüssel-sichern)).
{{< /note >}}

## Wenn etwas nicht klappt

| Was du siehst | Was du tun kannst |
|---|---|
| `hint: for changes waiting for your vote to reach you: juist admins receive` | Führe einmal `juist admins receive` aus. |
| `hint: once every device runs this version: juist log upgrade` | Aktualisiere juist auf allen Geräten, dann führe `juist log upgrade` aus. |
| `hint: bob cannot read it on an admin device yet; send them the file` | Schick bob die `.rec`-Datei, er ruft damit `juist approve FILE` auf. |
| `juist: no admin key of this network in …` | Führe den Befehl dort aus, wo der Schlüssel eines Admins liegt. |
| `juist: run as alice, without sudo: …` | Führe den Befehl noch einmal ohne sudo aus. |
| `….rec: outdated by a later change` | Wer die Änderung angestoßen hat, muss sie neu erstellen. |

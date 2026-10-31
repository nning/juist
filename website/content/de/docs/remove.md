---
title: Geräte entfernen
linkTitle: Geräte entfernen
description: Ein Gerät auf allen Geräten aus dem Netz nehmen, und wissen, wie schnell die anderen es fallen lassen.
lead: juist remove nimmt ein Gerät aus dem Netz, etwa ein verlorenes Handy. Jedes Gerät baut seinen Tunnel dorthin ab, sobald es davon erfährt. Ein Gerät, das von den anderen abgeschnitten ist, tut das spätestens, wenn seine Frische abläuft.
---

## Wie das Entfernen funktioniert

Ein Gerät zu entfernen ist eine Änderung am
[Mitgliederlog]({{< relref "docs/how-it-works" >}}#the-membership-log) und
braucht die Bestätigung deiner Admins. Jedes Gerät, das davon erfährt, baut
seinen Tunnel zum entfernten Gerät ab. Außerdem bekommt das Netz ein neues
Gruppengeheimnis, den Schlüssel, den alle Mitglieder teilen. Dadurch findet
das entfernte Gerät die anderen nicht mehr.

## Ein Gerät entfernen

{{< step on="dem Gerät eines Admins" >}}
Entferne das Gerät über seinen Namen, seine Adresse oder seinen Schlüssel.
`juist devices --keys` zeigt die Schlüssel; nimm `--all` dazu, wenn
Zugriffsregeln jenes Gerät von diesem trennen:

```sh
juist remove phone
```

```console
$ juist remove phone
remove phone (198.18.36.4  fd4c:8a21:e3f:e83:5a7d:f12c:9b46:d371) from "home"? [y/N] y
removed phone
```

Braucht die Änderung mehr als einen Admin, erscheint stattdessen
`pending …`, und die Änderung wartet, bis die anderen `juist approve`
ausführen ([Änderungen bestätigen]({{< relref "docs/network-changes" >}})).
{{< /step >}}

`juist log` enthält jetzt den Eintrag `device removal: phone` mit den Admins,
die ihn bestätigt haben.

## Was das entfernte Gerät sieht

Ist das Gerät erreichbar, während die Entfernung wirksam wird, erfährt es
davon:

```console {device="phone"}
$ juist status
home · removed

hint: 1 warning: juist health
$ juist health
warning: this device was removed from the network
hint: rejoin with a new invite, or start over: juist reset
```

Willst du es weiter nutzen, [lade es erneut ein]({{< relref "docs/invites" >}}),
oder führe `juist reset` aus. Dann gehört es zu keinem Netz mehr, wie nach
einer frischen Installation.

War das Gerät in diesem Moment offline, erfährt es nichts davon. Es zeigt
sich womöglich weiter als verbunden, obwohl kein Mitglied es mehr annimmt,
oder meldet `the network's devices refuse this one: most likely it was removed`.

## Warum das Entfernen nicht sofort wirkt

Die Geräte geben Änderungen untereinander weiter. Ein Gerät, das offline
oder abgeschnitten ist, erfährt vom Entfernen erst, wenn es wieder Kontakt
hat, und könnte bis dahin einen Tunnel zum entfernten Gerät halten. Die
[Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers) begrenzt
das auf 48 Stunden, aber erst, wenn das Netz einen Voucher hat:

{{< step on="dem Gerät eines Admins" >}}
Mach ein Gerät, das ständig läuft, etwa einen VPS, zum Voucher:

```sh
juist grant vps voucher
```

Mit der Rolle bekommt das Gerät keinen Admin-Schlüssel. Es bestätigt den
Stand des Netzes, kann aber nichts ändern.
{{< /step >}}

Ein lügender Voucher könnte die Geräte, die er erreicht, auf einem alten
Stand halten. Dagegen hilft es, zwei zu verlangen:

```sh
juist admins vouchers 2
```

Dann müssen zwei Voucher online sein, also gib die Rolle einem dritten Gerät
als Reserve. `juist grant` und `juist admins vouchers` warnen, wenn es keine
Reserve gibt.

## Gut zu wissen

- `juist remove` weigert sich, einen Voucher zu entfernen, den
  `juist admins vouchers` verlangt, und sagt, wie du die Zahl vorher senkst.
  Wer den letzten Voucher entfernt, wird gewarnt, dass die Frische dann nicht
  mehr geprüft wird.
- Lag auf dem entfernten Gerät ein Admin-Schlüssel, etwa auf einem verlorenen
  Laptop, entzieh diesem Schlüssel auch die Stimme: `juist admins remove`
  ([Admins]({{< relref "docs/admins" >}})).
- `juist reset` braucht `--force`, solange das Netz das Gerät noch führt.
  Entferne es vorher, wenn du kannst.

## Fehlersuche

`Freshness  expired; vouchers only` bedeutet, dass 48 Stunden lang zu wenige
Voucher erreichbar waren. `juist health` warnt einen Tag vorher mit
`freshness ends in …`. Bring einen Voucher wieder online. Sobald seine
Bestätigung ankommt, ist das Gerät wieder auf dem aktuellen Stand. Siehe
[Fehlersuche]({{< relref "docs/troubleshooting" >}}).

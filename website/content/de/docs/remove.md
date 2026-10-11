---
title: Geräte entfernen
linkTitle: Geräte entfernen
description: Ein Gerät auf allen Geräten aus dem Netz nehmen, und wissen, wie schnell die anderen es fallen lassen.
lead: juist remove nimmt ein Gerät aus dem Netz, etwa ein verlorenes Handy. Jedes Gerät baut seinen Tunnel dorthin ab, sobald es davon erfährt. Ein Gerät, das von den anderen abgeschnitten ist, tut das spätestens, wenn seine Frische abläuft.
---

## Wie das Entfernen funktioniert

Ein Gerät zu entfernen ist eine Änderung am Log des Netzes, also an der
signierten Liste, wer dazugehört (siehe
[So funktioniert juist]({{< relref "docs/how-it-works" >}})). Wie jede
Änderung müssen deine Admins sie bestätigen, also die Personen, deren
Schlüssel Änderungen bestätigen.

Sobald die Entfernung im Log steht, baut jedes Gerät, das davon erfährt,
seinen Tunnel zum entfernten Gerät ab. Außerdem bekommt das Netz ein neues
Gruppengeheimnis, also einen neuen Schlüssel, den alle Mitglieder teilen.
Dadurch findet das entfernte Gerät die anderen nicht mehr.

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
hint: rejoin with a new invite, or start over: juist reset
```

Willst du es weiter nutzen, [lade es erneut ein]({{< relref "docs/invites" >}}),
oder führe `juist reset` aus. Dann gehört es zu keinem Netz mehr, wie nach
einer frischen Installation.

War das Gerät in diesem Moment offline, erfährt es nichts davon. Es zeigt
sich womöglich weiter als verbunden, obwohl kein Mitglied es mehr annimmt,
oder meldet `the network's devices refuse this one: most likely it was removed`.

## Warum das Entfernen nicht sofort wirkt

Es gibt keinen Server, der allen Geräten gleichzeitig Bescheid gibt. Die
Geräte geben Änderungen untereinander weiter. Ein Gerät, das offline oder von
den anderen abgeschnitten ist, erfährt von der Entfernung also erst, wenn es
wieder Kontakt hat. Bis dahin könnte es noch einen Tunnel zum entfernten
Gerät halten.

Die Frische setzt dem eine Grenze. Ein **Voucher** ist ein Gerät, das
stündlich bestätigt, dass der Stand des Netzes aktuell ist. Ein neues Netz
hat keinen, die Grenze gilt also erst, wenn du einen ernennst. Hat ein Gerät
48 Stunden lang keine Bestätigung von einem Voucher bekommen, hält es nur noch
Tunnel zu Vouchern.
So kann es keine Verbindung zu einem entfernten Gerät aufrechterhalten. Sein
`juist status` zeigt dann den Zustand `limited` und
`Freshness  expired; vouchers only`.

Das funktioniert nur, solange die Voucher nicht zusammen mit dem Gerät
abgeschnitten sind. Ein Voucher hält jedes Gerät auf dem aktuellen Stand, das
er noch erreicht.

{{< step on="dem Gerät eines Admins" >}}
Mach ein Gerät, das ständig läuft, etwa einen VPS, zum Voucher:

```sh
juist grant vps voucher
```

Mit der Rolle bekommt das Gerät keinen Admin-Schlüssel. Es bestätigt nur den
Stand des Netzes und kann nichts ändern.
{{< /step >}}

In der Voreinstellung reicht ein Voucher. Ein Voucher, der lügt, könnte die
Geräte, die er erreicht, dann auf einem alten Stand halten. Dagegen hilft es,
mehrere Voucher zu verlangen:

```sh
juist admins vouchers 2
```

Jetzt hält ein Gerät seinen Stand nur dann für aktuell, wenn zwei Voucher ihn
innerhalb von 48 Stunden bestätigt haben. Ein einzelner unehrlicher Voucher
reicht dann nicht mehr, dafür müssen aber zwei Voucher online sein. Gib die
Rolle deshalb einem dritten Gerät als Reserve. `juist grant` und
`juist admins vouchers` warnen, wenn es keine Reserve gibt, und wenn nur ein
Voucher verlangt wird und ein Voucher zugleich Relay ist.

## Hinweise

- `juist remove` weigert sich, einen der Voucher zu entfernen, die `juist admins vouchers` verlangt, und erklärt, wie du die Zahl vorher senkst.
- Wer den letzten Voucher entfernt, bekommt eine Warnung, dass die Frische dann nicht mehr geprüft wird.
- Lag auf dem entfernten Gerät ein Admin-Schlüssel, etwa auf einem verlorenen Laptop, entzieh diesem Schlüssel auch seine Stimme: `juist admins remove`. Siehe [Admins]({{< relref "docs/admins" >}}).
- Rufst du `juist remove` auf dem Gerät selbst auf, warnt es, dass das Gerät das Netz endgültig verlässt.
- `juist reset` braucht `--force`, solange das Netz das Gerät noch als Mitglied führt. Entferne es nach Möglichkeit vorher.

## Fehlersuche

`Freshness  expired; vouchers only` bedeutet, dass 48 Stunden lang zu wenige
Voucher erreichbar waren. `juist status` warnt einen Tag vorher mit
`freshness ends in …`. Bring einen Voucher wieder online. Sobald seine
Bestätigung ankommt, ist das Gerät wieder auf dem aktuellen Stand. Siehe
[Fehlersuche]({{< relref "docs/troubleshooting" >}}).

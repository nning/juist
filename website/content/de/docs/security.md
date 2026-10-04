---
title: Sicherheit im Überblick
linkTitle: Sicherheit
description: Wem juist vertraut und wem nicht, wo die Schlüssel liegen und welche Schwächen es bewusst in Kauf nimmt.
lead: Was juist schützt, worauf es sich verlässt und wo seine Grenzen liegen, verständlich auch ohne Sicherheitswissen. Ein Sicherheitsaudit gab es für juist bisher nicht.
---

## Worum es geht

Bei juist entscheidet kein Server in der Mitte, wer zum Netz gehört. Das tun
deine Admins, indem sie Änderungen signieren, und jedes Gerät prüft diese
Änderungen selbst. Hier erfährst du, was daraus folgt: wem du vertrauen musst,
wo die Schlüssel liegen und was juist nicht leisten kann.

Die vollständige Analyse mit allen verbleibenden Schwächen steht im
[Bedrohungsmodell](https://github.com/nning/juist/blob/main/docs/02-threat-model.md)
(auf Englisch).

## Wem du vertraust

- Deinen Admins, aber nur gemeinsam. Jede Änderung, etwa das Aufnehmen oder
  Entfernen eines Geräts, braucht das Quorum, also so viele Admin-Stimmen, wie
  das Netz verlangt. Wer weniger Stimmen hat, kann allein nichts ändern, und
  das Log hält fest, wer welche Änderung signiert hat.
- Dem Anfang des Netzes. Jedes Gerät prüft jede Änderung im
  [Mitgliederlog]({{< relref "docs/how-it-works" >}}#the-membership-log)
  zurück bis zur allerersten, die beim Anlegen des Netzes entstanden ist.
- Jedem Mitglied. Ein aufgenommenes Gerät erreicht durch den Tunnel jeden Port
  jedes anderen Mitglieds. Zugriffsregeln gibt es in juist nicht.
- Einem Exit-Node, soweit es um den Verkehr geht, den er weiterleitet. Was du
  über einen [Exit-Node]({{< relref "docs/exit-nodes" >}}) ins Internet
  schickst, kann er mitlesen, genau wie jeder VPN-Anbieter.

## Wem du nicht vertrauen musst

- Den Wegen dazwischen. Jede Änderung ist signiert und wird von jedem Gerät
  geprüft, egal auf welchem Weg sie ankam. Den Verkehr zwischen Mitgliedern
  verschlüsselt WireGuard.
- Den öffentlichen Helfern. Der öffentliche BitTorrent-DHT und die
  STUN-Server helfen Geräten, einander zu finden. Sie können eine Verbindung
  verzögern, aber weder ändern, wer zum Netz gehört, noch Verkehr mitlesen.
  Sie sehen allerdings die Adressen der Geräte, die sie nutzen.
- Dem Relay. Ein [Relay]({{< relref "docs/relays" >}}) ist eines deiner
  eigenen Mitglieder, nur Mitglieder können es nutzen, und es sieht nur
  verschlüsselten WireGuard-Verkehr.
- Dem Daemon, wenn es ums Signieren geht. juistd bekommt nie einen
  Admin-Schlüssel. Auch ein kompromittierter juistd kann also keine Änderungen
  signieren.

## Wo die Schlüssel liegen

- Admin-Schlüssel liegen in deinem Keystore `~/.config/juist`, und zwar auf
  jedem Rechner, von dem aus du Änderungen bestätigst. Kopiere nie einen
  Schlüssel. Hast du zwei Laptops, erzeugst du auf jedem einen eigenen. Jedes
  Netz bekommt seinen eigenen Schlüssel, ein verlorener oder gestohlener
  Schlüssel betrifft also nur ein Netz.
- Die Schlüssel des Geräts selbst verwahrt juistd. Unter Linux legt das Paket
  sie in `/var/lib/juist` ab. juistd läuft unter einem eigenen Benutzer und
  hat nur `CAP_NET_ADMIN`. Der Befehl `juist` signiert nur, was er aus seinem
  eigenen geprüften Log nachvollzogen hat, ganz gleich, worum juistd ihn
  bittet.
- Die Break-glass-Geheimnisse, die `juist create` schreibt, liest kein
  juist-Befehl. Bewahre sie trotzdem offline auf.

## Wovor Einladungen schützen

Ein neues Gerät tritt mit einer [Einladung]({{< relref "docs/invites" >}})
bei. Sie schützt vor drei Dingen:

- Vor Raten. Mit einem Code gibt es genau einen Versuch, und der muss aus dem
  LAN kommen. Ein Link enthält ein 128-Bit-Geheimnis, das viel zu lang zum
  Raten ist.
- Vor einem Gerät, das sich dazwischenschaltet. Bevor etwas signiert wird,
  vergleicht der Admin vier Wörter mit dem neuen Gerät. Sie sind so gewählt,
  dass ein Angreifer dazwischen nicht nach passenden Wörtern suchen kann.
- Vor einem kompromittierten Daemon auf dem einladenden Gerät. Der Link bindet
  das neue Gerät an die Signatur des einladenden Admins. Dieser Daemon kann es
  also nicht in ein eigenes Netz locken.

## Ein Gerät entfernen, und wo das an Grenzen stößt

`juist remove phone` nimmt ein Gerät aus dem Netz. Dabei wird das
Gruppengeheimnis erneuert, mit dessen Hilfe die Mitglieder einander finden,
und jedes Mitglied baut seinen Tunnel zu dem Gerät ab, sobald es davon
erfährt. Mehr dazu unter [Ein Gerät entfernen]({{< relref "docs/remove" >}}).

Die Grenze: Ein Mitglied, das vom Rest abgeschnitten ist, erfährt erst spät
davon und behält bis dahin seinen Tunnel zum entfernten Gerät. Die Frische
begrenzt das auf 48 Stunden. Hat sich so lange kein Voucher für ein Mitglied
verbürgt, behält es nur noch Tunnel zu Vouchern. Ein **Voucher** ist ein
Gerät, das stündlich bestätigt, dass der Stand des Netzes aktuell ist. Mit
`juist admins vouchers M` hält diese Grenze auch dann, wenn M − 1 Voucher
lügen. Mehr dazu unter
[Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers).

Ein verlorenes oder gestohlenes Gerät bleibt Mitglied, bis du es entfernst.
Entferne es also, sobald du den Verlust bemerkst.

## Was juist in Kauf nimmt

Ohne Server in der Mitte ist manches schwächer. Unter
[Trade-offs]({{< home "trade-offs" >}}) steht zu jedem Punkt, was passieren
kann, warum juist das hinnimmt und was du dagegen tun kannst. Kurz gefasst:

- Gehen so viele Admin-Schlüssel verloren, dass kein Quorum mehr
  zusammenkommt, ist das Netz nicht mehr zu retten. Setze deshalb mehr Admins
  ein, als das Quorum braucht.
- Stehen alle Geräte eines Netzes hinter symmetrischem NAT, braucht es ein
  Mitglied als Relay.
- Der öffentliche DHT und die STUN-Server sehen die Adressen der Geräte, die
  sie nutzen, und sonst nichts. Mit einem eigenen Relay kommt juistd ohne sie
  aus.

## Quantencomputer

Ein künftiger Quantencomputer könnte heute übliche Verschlüsselung brechen.
Die Gruppengeheimnisse des Netzes sind dagegen geschützt, weil sie X25519 mit
ML-KEM-768 kombinieren. Für WireGuard-Verkehr gilt das nicht. Signaturen
verwenden Ed25519.

Verkehr, der heute mitgeschnitten wird, könnte also eines Tages entschlüsselt
werden. Für Verkehr, der jahrzehntelang geheim bleiben muss, solltest du dich
nicht auf juist verlassen.

## Gut zu wissen

- Ein Sicherheitsaudit gab es für juist bisher nicht.
- Unter Linux ist ein Dienst, der nur auf der juist-Adresse eines Geräts
  lauscht, trotzdem aus dem LAN dieses Geräts erreichbar. Dienste sollten
  deshalb selbst prüfen, wer sich verbindet.
- Jede Änderung am Netz steht mit den Namen derer, die sie bestätigt haben, in
  `juist log`.

## Eine Schwachstelle melden

Melde sie vertraulich über **Report a vulnerability** im
[Security-Tab des Repositorys](https://github.com/nning/juist/security), nicht
in einem öffentlichen Issue. Du bekommst innerhalb einer Woche eine Antwort,
und ein Fix erscheint, bevor die Einzelheiten veröffentlicht werden.

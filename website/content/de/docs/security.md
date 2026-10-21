---
title: Sicherheit im Überblick
linkTitle: Sicherheit
description: Wem juist vertraut und wem nicht, wo die Schlüssel liegen und welche Schwächen es bewusst in Kauf nimmt.
lead: Was juist schützt, worauf es sich verlässt und wo seine Grenzen liegen, verständlich auch ohne Sicherheitswissen. Ein Sicherheitsaudit gab es für juist bisher nicht.
---

## Wer entscheidet

Bei juist entscheidet kein Server in der Mitte, wer zum Netz gehört. Das tun
deine Admins, indem sie Änderungen signieren, und jedes Gerät prüft diese
Änderungen selbst. Hier erfährst du, was daraus folgt: wem du vertrauen musst,
wo die Schlüssel liegen und was juist nicht leisten kann.

Die vollständige Analyse mit allen verbleibenden Schwächen steht im
[Bedrohungsmodell](https://github.com/nning/juist/blob/main/docs/02-threat-model.md)
(auf Englisch).

## Wem du vertrauen musst

- Deinen Admins, aber nur gemeinsam. Jede Änderung, etwa das Aufnehmen oder
  Entfernen eines Geräts, braucht das Quorum, also so viele Admin-Stimmen, wie
  das Netz verlangt. Wer weniger Stimmen hat, kann allein nichts ändern, und
  das Log hält fest, wer welche Änderung signiert hat.
- Dem Anfang des Netzes. Jedes Gerät prüft jede Änderung im
  [Mitgliederlog]({{< relref "docs/how-it-works" >}}#the-membership-log)
  zurück bis zur allerersten, die beim Anlegen des Netzes entstanden ist,
  oder bis zu einem Checkpoint, den die Admins signiert haben.
- Jedem Mitglied, so weit die [Zugriffsregeln]({{< relref "docs/access" >}})
  es hereinlassen. Ohne Zugriffsregeln erreicht ein aufgenommenes Gerät durch
  den Tunnel jeden Port jedes anderen Mitglieds. Mit ihnen weist jedes Gerät
  ab, was keine Regel durchlässt, egal was der Absender tut.
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
  Sie sehen allerdings die Adressen der Geräte, die sie nutzen, und der DHT
  sieht, welche davon einander suchen. Geräte fragen zuerst die Relays des
  Netzes, und von den Geräten, die einander erreichen, fragt nur eines den
  DHT.
- Dem Relay. Ein [Relay]({{< relref "docs/relays" >}}) ist eines deiner
  eigenen Mitglieder. Nur Mitglieder können es nutzen, und es sieht nur
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
  sie in `/var/lib/juist` ab, und juistd läuft unter einem eigenen Benutzer
  und hat nur `CAP_NET_ADMIN`. Auf einem Telefon versiegelt die
  [Android-App]({{< relref "docs/android" >}}) sie mit einem Schlüssel, den
  der Android-Keystore hält.
- Der Befehl `juist` signiert nur, was er aus seiner eigenen geprüften Kopie
  des Logs nachvollzogen hat, ganz gleich, worum juistd ihn bittet.
- Das Break-glass-Geheimnis, das `juist create` einmal anzeigt und nirgends
  speichert, beendet das Netz endgültig, ganz ohne Admin. Bewahre es offline
  auf, getrennt von den Admin-Schlüsseln: Wer einen Tresor mit beidem hat,
  kann das Netz lenken und es beenden.

## Wovor Einladungen schützen

Ein neues Gerät tritt mit einer [Einladung]({{< relref "docs/invites" >}})
bei. Sie schützt vor drei Dingen:

- Vor Raten. Mit einem Code gibt es genau einen Versuch, und der muss aus dem
  LAN kommen. Ein Link enthält ein 128-Bit-Geheimnis, das viel zu lang zum
  Raten ist.
- Vor jemandem, der sich dazwischenschaltet. Bevor etwas signiert wird,
  vergleicht der Admin vier Wörter mit dem neuen Gerät. Sie decken jeden
  Schlüssel des neuen Geräts ab und sind so gewählt, dass ein Angreifer
  dazwischen nicht nach passenden Wörtern suchen kann. Damit sie
  übereinstimmen, brauchen beide Geräte dieselbe Version von juist.
- Vor einem kompromittierten Daemon auf dem einladenden Gerät. Der Link bindet
  das neue Gerät an die Signatur des einladenden Admins. Dieser Daemon kann es
  also nicht in ein Netz locken, das er selbst kontrolliert. Ein Code hat
  keinen solchen Anker: Das neue Gerät vertraut dem Netz, das sein Daemon ihm
  beim ersten Mal zeigt.

## Ein Gerät entfernen

`juist remove phone` nimmt ein Gerät aus dem Netz. Dabei wird das
Gruppengeheimnis erneuert, mit dessen Hilfe die Mitglieder einander finden.
Jedes Mitglied baut seinen Tunnel zu dem Gerät ab, sobald es davon erfährt.
Mehr dazu unter [Ein Gerät entfernen]({{< relref "docs/remove" >}}).

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

## Was juist bewusst in Kauf nimmt

Ohne Server in der Mitte ist manches schwächer. Unter
[Trade-offs]({{< home "trade-offs" >}}) steht zu jedem Punkt, was passieren
kann, warum juist das hinnimmt und was du dagegen tun kannst. Kurz gefasst:

- Gehen so viele Admin-Schlüssel verloren, dass kein Quorum mehr
  zusammenkommt, ist das Netz nicht mehr zu retten. Setze deshalb mehr Admins
  ein, als das Quorum braucht.
- Stehen alle Geräte eines Netzes hinter symmetrischem NAT, braucht es ein
  Mitglied als Relay.
- Der öffentliche DHT und die STUN-Server sehen die Adressen der Geräte, die
  sie nutzen. Ein Gerät sucht ein anderes im DHT, wenn es dessen Spur
  verloren hat und keines der Relays des Netzes weiß, wo es ist. Dann sieht
  der DHT, dass beide Adressen zu einem Netz gehören, aber nicht zu welchem
  und nicht, wem sie gehören. Von den Geräten, die einander erreichen, fragt
  nur eines. Mit einem eigenen Relay kommt juistd ohne sie aus.

## Quantensicher

Ein künftiger Quantencomputer könnte heute übliche Verschlüsselung brechen
und heute übliche Signaturen fälschen, und heute mitgeschnittener Verkehr
ließe sich dann entschlüsseln. juist schützt vor beidem:

- Jeder WireGuard-Handshake mischt einen Preshared Key ein. Zwei Geräte nutzen
  zuerst einen, der aus dem Gruppengeheimnis des Netzes abgeleitet ist. Sobald
  sie ihre Logs abgeglichen haben, wechseln sie zu einem, den nur die beiden
  haben: Jedes kapselt ein Geheimnis an den ML-KEM-768-Schlüssel des anderen.
  Dieser Schlüssel erneuert sich mit jeder Änderung der Mitglieder.
- Gruppengeheimnisse sind mit X25519 und ML-KEM-768 zusammen versiegelt.
- Jede Änderung am Netz und jede Nachricht, die Geräte füreinander signieren,
  ist mit ML-DSA-44 signiert, und eine Signatur allein mit Ed25519 wird
  abgewiesen. Nur Kopien der Ankündigung eines Geräts aus dem DHT, von einem
  Relay oder aus dem LAN werden mit Ed25519 allein angenommen, und sie sagen
  nicht mehr, als wo das Gerät zu erreichen ist. Der ML-DSA-Schlüssel jedes Geräts und jedes Admin-Schlüssels
  leitet sich aus dem Schlüssel ab, den es schon hat, also deckt dessen
  Backup ihn mit ab.
- Der Beitritt vereinbart nach der Prüfung von Code oder Link einen Schlüssel
  mit ML-KEM-768. Wer einen Beitritt mitschneidet und später einen
  Quantencomputer hat, erfährt daraus nichts.
- Relays und juists übrige Enden nehmen nur TLS 1.3 mit X25519 und
  ML-KEM-768 an, und Geräte, die nur HTTPS erreichen, verlangen es.
  Verbindungen durch den Ingress vereinbaren ihren Schlüssel so, wo immer die
  Gegenseite es anbietet, wie aktuelle Browser es tun.

Jeder Tunnel zwischen Geräten mit der aktuellen Version ist quantensicher.
Ein Gerät mit einer älteren Version bekommt nichts von deinem Verkehr, bis es
aktualisiert ist: `juist health` warnt, dass es ein älteres juist hat, und
`juist devices` zeigt es als `outdated`.

Die Grenze: Wer ein Gerät stiehlt und später einen Quantencomputer hat, liest,
was dieses Gerät lesen konnte, auch heute mitgeschnittenen Verkehr seiner
eigenen Tunnel. Entferne ein verlorenes Gerät sofort.

juist liest Netze, deren Log auf Schema 18 oder später steht, in denen jede
Änderung so signiert ist. Ein Netz, das mit einer älteren Version angelegt
wurde, liest es nicht mehr: Seine Admins legen es neu an, und seine Geräte
treten dem neuen bei.

Was klassisch bleibt: Ein Relay weist sich mit einem klassischen Zertifikat
aus, da ihm nur das Weiterreichen von Verkehr anvertraut ist, und ein Proxy,
der TLS ohne ML-KEM beendet, kann ein Gerät, das nur HTTPS erreicht, nicht
tragen.

## Hinweise

- Unter Linux verwirft juist Verkehr, der die juist-Adressen eines Geräts
  nicht durch den Tunnel erreicht, und Verkehr, der vorgibt, von einem
  Mitglied zu kommen, aber aus dem LAN eintrifft. Ein Container auf dem Gerät
  erreicht dessen eigene juist-Adresse deshalb nicht mehr.
- Unter FreeBSD ist ein Dienst, der nur auf der juist-Adresse eines Geräts
  lauscht, weiterhin aus dem LAN dieses Geräts erreichbar. Dienste sollten in
  jedem Fall selbst prüfen, wer sich verbindet.
- `juist log` zeigt jede Änderung am Netz und wer sie bestätigt hat.

## Eine Schwachstelle melden

Melde sie vertraulich über **Report a vulnerability** im
[Security-Tab des Repositorys](https://github.com/nning/juist/security), nicht
in einem öffentlichen Issue. Du bekommst innerhalb einer Woche eine Antwort,
und ein Fix erscheint, bevor die Einzelheiten veröffentlicht werden.

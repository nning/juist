---
title: Formale Verifikation
linkTitle: Formale Verifikation
description: Welche Protokolle und Regeln von juist maschinell gegen einen Angreifer geprüft werden, was gilt, was die Modelle finden und wo sie enden.
lead: Die eigenen Protokolle von juist und die Regeln seines Mitgliederlogs sind als formale Modelle geschrieben und werden maschinell geprüft, mit ProVerif und TLA+. Die Modelle prüfen den Entwurf, für kleine Netze; sie beweisen nicht, dass der Code korrekt ist.
---

## Wozu Modelle

juist baut auf bewährter Kryptografie auf: WireGuard, X25519, ML-KEM-768,
ML-DSA-44, SPAKE2. Wie es sie zusammensetzt, ist seine eigene Sache: der
Beitritt zu einem Netz, die Schlüssel, die je zwei Geräte teilen, und wie
Geräte zwischen gleichzeitig gemachten Änderungen wählen. Ein Fehler dort ist
ein Fehler im Entwurf, und ein Test des Codes findet ihn nur, wenn jemand an
den Fall gedacht hat.

Ein Modell beschreibt Entwurf und Angreifer genau, und ein Werkzeug probiert
dann alles aus, was der Angreifer tun kann, oder jede Reihenfolge, in der
Nachrichten ankommen können. Die Modelle haben so Fehler im Entwurf gefunden.
Zu jedem behobenen gehört ein Test, der ohne die Korrektur fehlschlägt; die
übrigen stehen [weiter unten](#was-die-modelle-finden).

## Die Werkzeuge

- **[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/)** 2.05, für
  die Protokolle. Der Angreifer beherrscht das Netz: Er liest, verwirft und
  wiederholt Nachrichten und schickt eigene, gebaut aus allem, was er weiß,
  über beliebig viele Sitzungen. Die Kryptografie gilt als perfekt. ProVerif
  beweist Geheimhaltung, dass eine Seite nur annimmt, was die andere wirklich
  geschickt hat, dass ein Code dem Raten offline widersteht und dass ein
  Angreifer zwei Situationen nicht unterscheiden kann.
- **[TLA+](https://lamport.azurewebsites.net/tla/tla.html)**, geprüft von
  TLC 1.8.0, für die Regeln, die über den Zustand entscheiden. TLC besucht
  jeden Zustand, den das Modell innerhalb seiner Schranken erreichen kann:
  jede Reihenfolge der Zustellung, jede verlorene oder wiederholte Nachricht.

## Was modelliert ist

| Modell | Code | Angreifer | Was gilt |
|---|---|---|---|
| Beitritt (`enroll*.pv`) | `trust/enroll` | das Netz, durchgehend aktiv; später ein Quantencomputer | Ein Einladungscode lässt sich offline nicht erraten und kostet online die Einladung ihren einen Versuch. Was das neue Gerät erhält, bleibt geheim, solange SPAKE2 oder ML-KEM-768 hält. Beide Seiten sind sich einig, was gesagt wurde, und aufgenommen werden nur die Schlüssel, deren Wörter der Admin verglichen hat. |
| Paarschlüssel (`pairkey*.pv`) | `internal/pairkey` | das Netz und ein drittes Mitglied, das das Gruppengeheimnis hält | Niemand außer den beiden Geräten erfährt ihren Schlüssel, und beide sind sich über Schlüssel und Epoche einig, bevor einer ihn verwendet. |
| Austausch der Paarschlüssel (`PairKey.tla`) | `internal/pairkey` | das Netz, das jede Nachricht verwirft, wiederholt und umsortiert; Epochenwechsel, zurückgesetzte Speicher eines Geräts | Der Schlüssel, den der Folgende verwendet, ist einer, den der Führende probiert; zwei Seiten auf einer Generation haben denselben Schlüssel abgeleitet; eine alte Nachricht setzt keinen Schlüssel zurück; keine Generation wird zweimal verwendet. |
| Nachholen verpasster Schlüssel (`catchup.pv`) | `gossip` | das Netz und ein entferntes Gerät mit jedem Schlüssel, den es je hatte | Schlüssel bekommt nur ein gelistetes Mitglied, das sich für diese Anfrage ausgewiesen hat; das entfernte Gerät bekommt nichts. |
| Änderungen, die auf Stimmen warten (`waiting.pv`) | `internal/waiting` | das Netz und jeder Daemon, auch der von Admin-Geräten | Eine wartende Änderung öffnet sich nur für die Admin-Schlüssel, an die sie versiegelt ist, und nur so, wie ihr Unterzeichner sie vorgeschlagen hat. |
| Treffen mit dem einladenden Gerät (`relay.pv`) | `relay/forward`, `internal/rendezvous` | das Netz, ein Relay des Angreifers, die Knoten der DHT | Das Geheimnis des Links bleibt bei den beiden Geräten; ein Relay nimmt eine Anmeldung nur von dem Mitglied an, das sie gemacht hat; das neue Gerät wählt nur die Adressen an, die das einladende Gerät veröffentlicht hat, und die bleiben versiegelt. |
| Ersetzen eines veralteten Logs (`rebase.pv`) | `internal/guest`, `trust/log` | der einladende Daemon, das Netz und ein entfernter Admin, dem das Gerät noch vertraut | Ein Gerät ersetzt sein Log nur durch eine Kette, die der im Link genannte Admin geprüft und in die er es aufgenommen hat. |
| Das Mitgliederlog (`Log.tla`) | `trust/log` | das Netz, das jede Änderung in beliebiger Reihenfolge oder gar nicht zustellt; ein kompromittierter Admin unterhalb des Quorums; ein entfernter Admin | Jede Änderung auf einer Kette hat ihr Quorum; kein Gerät vertraut einem Zustand unterhalb der Epochenschwelle; ein entfernter Schlüssel macht keine Entfernung rückgängig, auch bei Personen mit mehreren Schlüsseln und bei Kopien einer Änderung. Geräte, die dieselben Änderungen hören, halten denselben Stand oder schlagen alle Alarm, solange keines kompaktiert. |
| Frische (`Freshness.tla`) | `trust/log` | das Netz, das einem Mitglied eine Entfernung vorenthält; bis zu M − 1 lügende Voucher; Uhren, die abweichen | Ein Mitglied, das von einer Entfernung abgeschnitten ist, weist das entfernte Gerät spätestens ab, sobald seine Bestätigung abgelaufen und die doppelte Uhrenabweichung vergangen ist. |

Jede Modelldatei nennt in ihren ersten Zeilen ihren Angreifer und ihre
Vereinfachungen, in [`models/`](https://github.com/nning/juist/tree/main/models)
(auf Englisch).

## Was die Modelle finden

ProVerif und TLC finden auch Angriffe. Das sind bekannte Grenzen von juist,
wie es ist, festgehalten als erwartete Ergebnisse, damit der Lauf
fehlschlägt, wenn eines unbemerkt verschwindet oder ein neues auftaucht:

- **Keine Forward Secrecy für Paarschlüssel.** Wer den Verkehr eines Paars
  aufzeichnet und später beide Geräte stiehlt, erfährt ihren Paarschlüssel.
  Mit einem Quantencomputer, der WireGuards eigenen Handshake bricht, öffnet
  das den aufgezeichneten Verkehr.
- **Eine wartende Änderung lässt sich erraten.** Ein Daemon, der eine
  wartende Änderung ohne neues Gruppengeheimnis trägt, etwa das Entfernen
  eines Admin-Schlüssels, kann durch Ausprobieren jedes Kandidaten
  herausfinden, welche es ist.
- **Eine wiederhergestellte Paardatei kann einen Tunnel trennen.** Ein Gerät,
  dessen Paardatei aus einer älteren Kopie wiederhergestellt wird, kann einen
  Schlüssel halten, über den sein Gegenüber schon hinaus ist, bis die Datei
  entfernt wird.
- **Kompaktieren kann Geräte spalten.** Eine Änderung unterhalb eines
  Checkpoints wird von Geräten, die kompaktiert haben, abgewiesen und von
  den anderen angenommen. Beide halten dann unterschiedliche Mitglieder, und
  keines schlägt Alarm.
- **Ein angehobenes Quorum kann rückgängig gemacht werden.** Admins, die
  zusammen das Quorum hatten, bevor eine Änderung es anhob, können an
  derselben Stelle im Log eine Entfernung signieren und sie neu ziehen, bis
  ihre gewinnt; das macht die Anhebung und alles danach rückgängig.

Das [Bedrohungsmodell](https://github.com/nning/juist/blob/main/docs/02-threat-model.md)
führt die ersten vier unter seinen verbleibenden Schwächen, mit dem, was sie
begrenzt.

## Wie die Modelle an den Code gebunden bleiben

Ein Modell prüft, was es beschreibt, nicht, was der Code tut. Drei Dinge
verbinden beides, und `make check` führt sie bei jedem Push aus:

- Jedes Protokollmodell nennt die Labels und Felder, die der Code verwendet,
  in ihrer Reihenfolge. Ein Test schlägt fehl, wo der Code davon abweicht.
- TLC schreibt Abläufe des Logs und des Paarschlüsselaustauschs: was jedes
  Gerät nach jedem Schritt halten sollte. Tests spielen sie gegen
  `trust/log` und `internal/pairkey` ab und schlagen fehl, wo der Code etwas
  anderes hält.
- Zu jedem Protokoll gehört ein Modell eines ehrlichen Ablaufs, den ProVerif
  finden muss, damit ein Beweis nicht nur deshalb gilt, weil nie etwas
  geschieht.

## Wo sie enden

- Die Kryptografie gilt als perfekt. Die Modelle zeigen nicht, dass SPAKE2
  und ML-KEM-768 stark genug sind oder ihre Kombination es ist, und sie sehen
  kein Timing.
- Signaturen und Verschlüsselung sind vereinfacht: Ed25519 und ML-DSA zählen
  als eine Signatur, X25519 und ML-KEM-768 als eine Verschlüsselung. Ein
  Fehler, der eine der beiden Hälften gebrochen voraussetzt, bleibt unsichtbar.
- TLC prüft kleine Netze: zwei Geräte, drei Admin-Schlüssel, höchstens drei
  Änderungen, und beim Paarschlüssel drei Generationen über zwei Epochen.
  Änderungen an den Stimmen einer Person, Schema-Upgrades, das Sperren eines
  Mitglieds und der Wechsel einer Identität sind nicht im Modell des Logs.
- WireGuard ist nicht modelliert; dafür gibt es eigene veröffentlichte
  Beweise. Ebenso wenig die Verschlüsselungshelfer von juist,
  Standardkonstruktionen, die im Review gelesen werden.
- Die Modelle laufen von Hand, nicht in CI: Alle zusammen brauchen auf vier
  Kernen etwa drei Stunden. Der letzte Lauf, seine Revision und die
  Werkzeugversionen stehen in
  [12-validating.md](https://github.com/nning/juist/blob/main/docs/12-validating.md)
  (auf Englisch).

Ein Beweis über ein Modell ist ein Beleg für den Entwurf, nicht für jede
Zeile des Codes, und er ersetzt kein Sicherheitsaudit. Siehe
[Qualitätssicherung]({{< relref "docs/quality-assurance" >}}).

## Selbst ausführen

Mit ProVerif 2.05, einem JDK und TLCs `tla2tools.jar` 1.8.0:

```sh
make models TLA2TOOLS=/pfad/zu/tla2tools.jar
```

Das führt jedes Modell aus und schlägt fehl, wo ein Ergebnis nicht das ist,
das `models/expected` festhält. `make model-traces` schreibt die Abläufe, die
die Tests abspielen, neu.

---
title: Qualitätssicherung und Sicherheit
linkTitle: Qualitätssicherung
description: Wie juist agentisch geschriebenen Code prüft, was die Tests belegen und wo ihre Aussagekraft endet.
lead: juist wird mit KI-Agenten entwickelt. Vertrauen stützt sich auf einsehbaren Code, Tests und dokumentierte Prüfungen, nicht auf den Verfasser. Ein menschliches Sicherheitsaudit gab es bisher nicht.
---

## Was agentische Entwicklung hier bedeutet

juist wird mit KI-Agenten entwickelt, unter Einsatz von Opus 5.5. Agenten
schreiben Code und Tests und prüfen Änderungen. Die README nennt diese
Herkunft ausdrücklich, damit du sie vor der Installation eines VPNs auf
deinen Geräten berücksichtigen kannst.

Ein Modell kann eine Anforderung missverstehen und einen Test schreiben,
der denselben Fehler wiederholt. Auch ein weiteres Modellreview kann ihn
übersehen. Erfolgreiche Tests belegen die geprüften Fälle, nicht die
Fehlerfreiheit der Implementierung oder ihres Sicherheitsentwurfs.
Agentische Entwicklung senkt den Anspruch des Projekts nicht; Automatisierung
allein belegt aber auch nicht, dass alle Anforderungen erfüllt sind.

## Was geprüft wird

Die Prüfungen stehen im Repository zum Nachlesen und Ausführen bereit:

| Prüfung | Aussage und Grenze |
|---|---|
| `make check` | Formatierung, statische Analyse, Konsistenz der Abhängigkeitsdateien, Builds, Tests mit Race Detector, Kerngröße und reproduzierbare Builds. Ohne die erforderlichen Privilegien und Systemfunktionen werden Netzwerktests übersprungen. |
| Angriffs- und Eigenschaftstests | Abweisung gefälschter Signaturen, unzureichender Quoren, wiederholter und zurückgerollter Änderungen; Konvergenz und unveränderter Zustand nach abgelehnten Einträgen. Geprüft werden konkrete Angriffe und erzeugte Fälle. |
| `make ci-vm` | Privilegierte Linux-Netzwerktests, ein Labor mit installierten Paketen, Zusammenspiel von Linux und FreeBSD, Cross-Builds und eine Schwachstellenprüfung der Abhängigkeiten. So werden Geräte, Routen, NAT und Paketlebenszyklen über Tests innerhalb eines Prozesses hinaus geprüft. |
| Fuzz-Targets | Parser und Validatoren bekommen erzeugte fehlerhafte Eingaben. Ein kurzer Probelauf und eine lange Kampagne liefern unterschiedlich viel Evidenz; ein vorhandenes Target belegt keinen langen Lauf. |
| Regressionstests | Zu einem behobenen Befund gehört ein Test, der bei zurückgenommener Korrektur nachweislich fehlschlägt und mit ihr besteht. Das prüft, ob der Test den Fehler erkennt. |

Vor jedem Push ist `make check` vorgeschrieben. Langsamere Prüfungen richten
sich nach dem betroffenen Verhalten; vor einem Release ist der vollständige
VM-Lauf erforderlich. Lange Fuzz-Kampagnen laufen getrennt von CI. Der
dokumentierte Nachweis langer Läufe umfasst derzeit ein QUIC-Parser-Target,
nicht jede Eingabefläche.

Ein übersprungener Test ist kein bestandener Test. Echte TUN-Geräte und
Netzwerk-Namespaces brauchen Privilegien; ein erfolgreicher unprivilegierter
Lauf sagt über diese Prüfungen nichts aus. Cross-Kompilierung allein belegt
nicht, dass eine Plattform funktioniert. Handtests ergänzen das Labor für
echte Netze, Telefone und installierte Pakete.

## Sicherheit gehört zum Entwurf

Der [Sicherheitsüberblick]({{< relref "docs/security" >}}) beschreibt die
Vertrauensgrenzen: Geräte prüfen das signierte Mitgliederlog selbst,
Admin-Schlüssel bleiben außerhalb des Daemons, und das empfangende Gerät
setzt Zugriffsregeln durch. Dort stehen auch die verbleibenden
Vertrauensannahmen und Grenzen beim Entfernen von Geräten, bei der
Schlüsselverwahrung und beim Datenschutz der Gerätesuche.

Das Repository ordnet sicherheitsrelevanten Code einem ausdrücklichen
[Prüfumfang](https://github.com/nning/juist/blob/main/audit-scope) zu. `make tcb` prüft, dass Pakete eingeordnet sind, und begrenzt
die Größe des Vertrauenskerns. Ein kleinerer Kern erleichtert Reviews;
eine Zeilenzahl ist kein Sicherheitszertifikat. Bewährte kryptografische
Bausteine allein bestätigen weder die Protokolle von juist noch den Code, der
sie verbindet.

Prüfsummen der Releases werden signiert; Reproduzierbarkeitsprüfungen
vergleichen Builds. Das hilft nachzuvollziehen, welches Artefakt du erhalten
hast und wie es gebaut wurde. Es belegt nicht, dass sein Code sicher ist.
Siehe [Installation und Downloadprüfung]({{< relref "docs/install" >}}).

## Welche Belege du nachlesen kannst

Im Quellrepository stehen das
[Bedrohungsmodell](https://github.com/nning/juist/blob/main/docs/02-threat-model.md),
die [Teststrategie](https://github.com/nning/juist/blob/main/docs/06-verification.md)
und die [Prüfanleitungen mit dokumentierten Läufen](https://github.com/nning/juist/blob/main/docs/12-validating.md)
(auf Englisch). Sie beschreiben geprüfte Eigenschaften, verbleibende Lücken
sowie Revision und Umgebung der festgehaltenen Läufe. Beziehe Ergebnisse
auf die Version, die du nutzt: Ein bestandener Lauf bestätigt nicht jede
spätere Änderung.

## Reicht das für deinen Einsatz?

juist hat bisher kein Sicherheitsaudit erhalten. Modellreviews,
automatisierte Tests und der Einsatz auf echten Geräten liefern nützliche
Belege, ersetzen aber kein unabhängiges menschliches Sicherheitsaudit.
Unbekannte Schwachstellen oder gemeinsame Fehler in Implementierung, Tests
und Dokumentation schließen sie nicht aus.

Die Grundlage zur Beurteilung ist damit konkret, aber begrenzt: einsehbarer
Quellcode, wiederholbare Prüfungen, dokumentierte Vertrauensgrenzen und
offengelegte Lücken. Ob das genügt, hängt davon ab, was dein Netz schützt
und welche Folgen ein Fehler hätte. Benötigst du unabhängig auditierte
Software, erfüllt juist diese Anforderung nicht.

Melde einen möglichen Sicherheitsfehler vertraulich über den
[Security-Bereich des Repositorys](https://github.com/nning/juist/security).

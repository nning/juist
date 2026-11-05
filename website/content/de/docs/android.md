---
title: Android
linkTitle: Android
description: Die Android-App von juist installieren, mit einem Telefon per QR-Code oder Code einem Netz beitreten, die Geräte beim Namen erreichen und auf dem Telefon sehen, wie jedes erreicht wird.
lead: Mit der Android-App wird ein Telefon Mitglied eines Netzes. Es tritt per QR-Code oder Code der Einladung bei, erreicht die anderen Geräte unter Namen und Adresse und zeigt, wie jedes erreicht wird.
---

## Was die App kann

Die App bringt juist auf ein Telefon mit Android 12 oder neuer. Das Telefon
tritt einem Netz als Mitglied ohne Rollen bei. Solange sein VPN an ist,
erreicht jede App auf dem Telefon die anderen Geräte unter ihrem Namen, etwa
`nas.home.juist`, und unter ihrer Adresse, dazu die LANs hinter ihren
[Subnet-Routern](#subnets). Das VPN trägt nur den Verkehr ins Netz, in diese
Subnetze und das DNS des Telefons ([Namen](#names)); aller übrige Verkehr
geht an juist vorbei.

Das Telefon kann nicht:

- in mehr als einem Netz sein;
- [öffentliche Namen]({{< relref "docs/names" >}}) einschalten, sie lösen
  sich dort also öffentlich auf;
- ein Subnetz routen oder [Exit-Node]({{< relref "docs/exit-nodes" >}}) sein,
  wohl aber beides nutzen;
- Geräte einladen, einen Admin-Schlüssel halten oder weiterleiten.
  Einladungen kommen vom Rechner eines Admins.

## Die App installieren

Installiere die App mit F-Droid, das dann jedes neue Release bringt, oder
lade sie einmal von GitHub herunter.

### Mit F-Droid

1. Installiere [F-Droid](https://f-droid.org) auf dem Telefon, falls es dort
   noch fehlt. Ein anderer Client für F-Droid-Paketquellen, etwa Droid-ify,
   geht auch.
2. Tippe auf dem Telefon auf
   [Paketquelle von juist zu F-Droid hinzufügen](fdroidrepos://pkg.juist.nning.io/juist/android/repo?fingerprint=0AAB0ADFA407BE52D9FB3AF3C0426FF0CDF4CA67CEBBFD981EA29EF0BD373C30)
   und bestätige in F-Droid. Oder kopiere diese Adresse, öffne in F-Droid
   **Paketquellen**, tippe auf **+** und füge sie ein:

   ```text
   https://pkg.juist.nning.io/juist/android/repo?fingerprint=0AAB0ADFA407BE52D9FB3AF3C0426FF0CDF4CA67CEBBFD981EA29EF0BD373C30
   ```

3. Suche in F-Droid nach **juist** und installiere es. Android fragt, ob
   F-Droid Apps installieren darf.

F-Droid aktualisiert die App mit jedem Release. Am Fingerabdruck in der
Adresse prüft es, dass die Paketquelle die von juist ist.

### Von GitHub

Lade auf dem Telefon `juist-android-arm64.apk` aus dem
[neuesten Release](https://github.com/nning/juist/releases/latest) herunter
und öffne sie. Android fragt, ob der Browser Apps installieren darf. Zum
Aktualisieren installierst du die APK des nächsten Releases darüber, oder du
fügst die F-Droid-Paketquelle hinzu, die auch eine so installierte App
aktualisiert.

### Die App prüfen

Die App ist mit dem Release-Schlüssel von juist signiert. Der
SHA-256-Fingerabdruck ihres Zertifikats lautet:

```text
51:5C:14:80:41:8A:98:4A:8B:1A:E3:69:51:7A:2C:9F:7F:48:A2:19:41:0C:AE:E6:6F:B5:82:EF:EC:AB:E5:21
```

`apksigner verify --print-certs juist-android-arm64.apk` zeigt ihn an. Die
APK steht auch in `SHA256SUMS`
([Einen Download prüfen]({{< relref "docs/install" >}}#verifying-a-download)).

Eine [selbst gebaute](https://github.com/nning/juist/blob/main/android/README.md)
App ist mit einem anderen Schlüssel signiert. Sie lässt sich deshalb nicht
über ein Release installieren und umgekehrt.

## Einem Netz beitreten

{{< screens >}}
welcome: Der erste Bildschirm: QR-Code scannen oder Code eintippen
joining_words: Die vier Wörter, die der Admin vergleicht
{{< /screens >}}

{{< step on="dem Gerät eines Admins" >}}
Starte eine Einladung in einem Terminal mit mindestens 60 Spalten, damit es
den QR-Code zeigt:

```sh
juist invite
```
{{< /step >}}
{{< step on="dem Telefon" >}}
Öffne juist, tippe auf **QR-Code scannen** und richte die Kamera auf den
QR-Code.

Oder tippe auf **Code eintippen** und gib den Code ein, etwa
`42-drumbeat-tolerance-glucose`. Ein Code funktioniert nur im selben LAN wie
das einladende Gerät. Anderswo scannst du den QR-Code oder fügst den Link in
dasselbe Feld ein.
{{< /step >}}
{{< step on="dem Telefon" >}}
Prüf den Namen des Telefons im Netz, etwa `pixel-8`. Tippe auf
**Beitreten** und erlaube das VPN, wenn Android fragt. Das Telefon zeigt dann
vier Wörter.
{{< /step >}}
{{< step on="dem Gerät eines Admins" >}}
Vergleiche sie mit den Wörtern, die die Einladung zeigt. Stimmen sie,
antworte mit `y`. Sonst antworte mit `n` und brich auf dem Telefon ab.
{{< /step >}}

Braucht das Netz die Stimmen mehrerer Admins, zeigt das Telefon
`Waiting for approval: 1 of 2 votes`, bis die anderen bestätigt haben.
[Geräte einladen]({{< relref "docs/invites" >}}) erklärt Code, Link und
Wörter.

## Der Statusbildschirm

{{< screens >}}
status: Das Netz, dieses Telefon und was Aufmerksamkeit braucht
member: Ein Gerät, mit einem Ping durch den Tunnel
{{< /screens >}}

Die App zeigt, was `juist status`, `juist health` und `juist devices` auf
einem Rechner zeigen ([Status und Geräte]({{< relref "docs/status" >}})):
den Zustand des Netzes, was Aufmerksamkeit braucht, Namen, Adressen und
Frische dieses Telefons und wie jedes andere Gerät erreicht wird. Tippe auf
eine Adresse, um sie zu kopieren.

| Zustand | Bedeutung |
|---|---|
| Verbunden | das Telefon erreicht die Geräte des Netzes |
| Wartet auf Geräte | noch kein anderes Gerät hat sich gemeldet |
| Kein Tunnel steht | die Geräte sind bekannt, aber zu keinem fließt Verkehr |
| Eingeschränkt | kein Voucher hat den Stand des Telefons zuletzt bestätigt, also erreicht es nur Voucher |
| Entfernt | das Telefon gehört nicht mehr zum Netz |
| Abgewiesen | die Geräte des Netzes weisen das Telefon ab, wahrscheinlich wurde es entfernt |
| Getrennt | die Geschichte des Netzes hat sich gespalten, und alle Tunnel sind unterbrochen, bis ein Admin das klärt |
| Aus | das VPN ist aus |

Ein Gerät wird **Direkt** oder **Über ein Relay** erreicht, oder gerade
nicht: **Keine Antwort**, **Wird gesucht**, **Offline**,
**Noch nicht gemeldet**, **Noch nicht geprüft** oder **Veraltet** (es läuft
ein älteres juist, und bis zum Update kommen nur Pings durch).

Tippe auf ein Gerät, um Namen, Adressen, Rollen, das Schema seines juist und
den letzten Kontakt zu sehen. **Ping** schickt ein Echo durch den Tunnel, das
juist auf dem Gerät beantwortet, auch wenn dessen Firewall Pings verwirft.
**Im Browser öffnen** öffnet `http://` mit seiner Adresse.

{{< screens >}}
member_services: Die Dienste eines Geräts: veröffentlichte Namen, ein TCP-Port und ein Subnetz
{{< /screens >}}

Unter **Dienste** listet der Bildschirm eines Geräts, was das Netz auf ihm
veröffentlicht ([Dienste veröffentlichen]({{< relref "docs/publishing" >}})):
Ein Name öffnet sich im Browser, ein TCP-Port und ein Subnetz werden beim
Antippen kopiert. Namen nur für Mitglieder sagen das.

## Details

{{< screens >}}
details: Die Einstellungen des Telefons, Schema, Relays und Subnetze des Netzes und die letzten Änderungen im Log
{{< /screens >}}

**Details**, unter den Geräten oder im Menü, zeigt, was `juist status` und die
[Statusseite]({{< relref "docs/publishing" >}}#status-page) über den Zustand hinaus
zeigen: das Schema des Netzes neben dem der App, den Kopf des Logs, wann das
Telefon seine Sicht auf das Netz zuletzt aktualisiert hat, die Relays und das,
über das das Telefon läuft, die Namen des Netzes, seine Subnetze und die
letzten Änderungen im Log, wie `juist log` sie listet.

Dort liegen auch die zwei Einstellungen des Telefons:

- **Namen im Netz**: Jede Abfrage geht an juist, das die Namen des Netzes
  beantwortet. Aus, behält das Telefon sein eigenes DNS und löst keinen davon
  auf, wie `juist set --dns=false` auf einem Rechner.
- **Nur HTTPS**: Das Telefon erreicht Relays nur über HTTPS auf Port 443, wie
  mit `juist set --https-only` ([Netze, die nur HTTPS
  durchlassen]({{< relref "docs/https-only" >}})).

Unter **Diagnose** zählt die App, wie oft sie das VPN eingerichtet hat und wie
ihre Abfragen liefen: wie viele fehlschlugen oder langsam waren, und welche.
**Protokoll kopieren** fügt hinzu, wie Android die Netze des Telefons sieht.

## Subnetze {#subnets}

Gibt das Netz einem Mitglied ein [Subnetz]({{< relref "docs/subnets" >}}),
etwa das LAN zu Hause, erreicht das Telefon es über dieses Mitglied, solange
das VPN an ist. Ein Subnetz, das das eigene Netz des Telefons schon abdeckt,
etwa dieses LAN, während das Telefon in seinem WLAN ist, bleibt außerhalb des
Tunnels, und **Details** sagt das. Im Mobilnetz geht es wieder durch den
Tunnel.

## Namen {#names}

{{< screens >}}
status_private_dns: Was die App sagt, während Privates DNS an juist vorbeigeht
{{< /screens >}}

Solange das VPN an ist, geht jede Namensabfrage auf dem Telefon an juist in
der App. Es beantwortet die [Namen]({{< relref "docs/names" >}}) des Netzes,
etwa `nas.home.juist` oder nur `nas`, und die unter der Domain des Netzes
[veröffentlichten]({{< relref "docs/publishing" >}}) Namen, die dann direkt
zu ihrem Gerät führen. Auch Rückwärtsabfragen der Adressen des Netzes
beantwortet es. Alle anderen Namen gehen wie ohne juist an das Netz, in dem
das Telefon ist, über DNS over TLS, wenn Privates DNS auf automatisch steht
und es nutzen würde. Schaltest du das VPN aus, bekommt das Telefon sein
eigenes DNS zurück.

Ob Abfragen juist erreichen, entscheidet die Android-Einstellung
**Privates DNS**:

| Privates DNS | Namen des Netzes |
|---|---|
| Aus | werden aufgelöst |
| Automatisch | werden aufgelöst |
| Hostname des privaten DNS-Anbieters | werden nicht aufgelöst: Android schickt jede Abfrage an diesen Anbieter |

Ist ein Anbieter eingetragen, sagt die App, dass die Namen des Netzes nicht
aufgelöst werden, und nennt jeden
[Namen nur für Mitglieder]({{< relref "docs/members-only" >}}), der dann
unerreichbar ist.

## Über einen Exit-Node

Hat das Netz [Exit-Nodes]({{< relref "docs/exit-nodes" >}}), listet der
Statusbildschirm sie unter **Internet** auf, neben **Direkt**. Wählst du
einen, laufen Internetverkehr und DNS des Telefons über ihn. Die Namen des
Netzes beantwortet weiter juist. Solange der Exit-Node nicht nutzbar ist,
wird der Internetverkehr gesperrt, nicht direkt geschickt, und die App sagt
warum. Mit **Direkt** geht es wieder ohne ihn.

Stoppt juist, schickt Android den Verkehr direkt. Soll er stattdessen
gesperrt werden, schalte für juist **Durchgehend aktives VPN** und
**Verbindungen ohne VPN blockieren** in den VPN-Einstellungen von Android
ein. Die App verlinkt dorthin.

## Das VPN aus- und einschalten

Der Schalter neben dem Zustand schaltet das VPN aus und ein, ebenso die
Kachel von juist in den Schnelleinstellungen von Android: Füge sie beim
Bearbeiten der Kacheln hinzu; lang gedrückt öffnet sie die App. Solange es an
ist, zeigt eine Benachrichtigung den Zustand, mit der Aktion **Ausschalten**.
War das VPN an, schaltet juist es nach einem Neustart oder Update wieder ein.
Android betreibt immer nur ein VPN: Eine andere VPN-App schaltet juist ab, und
die App sagt das.

## Akku

juist spart Akku, solange der Bildschirm aus ist, das Telefon ruht oder der
Energiesparmodus an ist, und im Mobilnetz oder an einem Hotspot, solange die
App nicht im Vordergrund ist. Es prüft dann die anderen Geräte und gleicht
das Log seltener ab und lauscht nicht mehr auf das Multicast-DNS des WLANs.
Änderungen am Netz kommen trotzdem sofort an, und der Verkehr durch den
Tunnel wird nicht langsamer.

Läuft das Netz mit dem Schema der App
([juist aktualisieren]({{< relref "docs/updating" >}})), lassen auch die
anderen Geräte das Telefon schlafen: Sie prüfen es seltener und überlassen
ihm den Log-Abgleich. Ein Mitglied erreicht ein schlafendes Telefon trotzdem
sofort.

## Wenn das Telefon entfernt wird

Ein Admin entfernt das Telefon wie jedes Gerät: `juist remove pixel-8`
([Ein Gerät entfernen]({{< relref "docs/remove" >}})). Die App zeigt dann
**Entfernt**. Tippe auf **Netz vergessen**, um mit neuen Schlüsseln neu
anzufangen, und tritt mit einer neuen Einladung wieder bei.

Willst du juist auf dem Telefon nicht mehr nutzen, lass es zuerst von einem
Admin entfernen und deinstalliere dann die App. Ein nur deinstalliertes
Telefon führt das Netz weiter.

## Privatsphäre und Sicherheit

- Die Schlüssel des Telefons sind mit einem AES-256-Schlüssel im Android
  Keystore versiegelt, im Sicherheitschip des Telefons, wenn es einen hat.
  Eine Kopie der App-Dateien lässt sich auf keinem anderen Telefon öffnen.
- Nichts von juist landet in einem Backup oder auf einem neuen Telefon. Ein
  neues Telefon tritt mit einer eigenen Einladung bei.
- Die Kamera liest nur den QR-Code. Nichts, was sie sieht, wird gespeichert
  oder verschickt.
- **Über juist** im Menü zeigt Version und Lizenzen. **Protokoll kopieren**
  kopiert das Log der App, das nur im Speicher liegt, mit dem, wie Android die
  Netze des Telefons sieht, und den fehlgeschlagenen Abfragen. Es nennt deine
  Geräte und Adressen; gib es nur jemandem, dem du vertraust.

## Fehlersuche

| Du siehst | Was zu tun ist |
|---|---|
| **Nicht beigetreten** | Die Einladung ist abgelaufen, verbraucht, oder das einladende Gerät ist nicht erreichbar. Starte eine neue Einladung. Ein Code funktioniert nur im selben LAN; scanne stattdessen den QR-Code. |
| **Kein Gerät darf weiterleiten** | Ein Telefon im Mobilnetz braucht oft ein Relay. Ein Admin gibt einem Gerät mit öffentlicher Adresse die Rolle `relay` ([Relays]({{< relref "docs/relays" >}})). |
| **Eingeschränkt** | Das Telefon hat 48 Stunden lang zu wenige Voucher erreicht. Verbinde es mit einem Netz, in dem es sie erreicht. |
| **Zu wenige Voucher haben bestätigt: eingeschränkt in … Stunden** | Bring vorher einen Voucher wieder online. |
| **Abgewiesen** oder **Entfernt** | Das Telefon wurde entfernt. Vergiss das Netz und tritt mit einer neuen Einladung wieder bei. |
| **Privates DNS schickt jede Anfrage an …** | Stell Privates DNS in den Netzwerkeinstellungen des Telefons auf automatisch oder aus. |
| `nas.home.juist` wird nicht aufgelöst | Schalte das VPN ein. Sonst sagt der Statusbildschirm, warum. |

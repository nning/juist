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
`nas.home.juist`, und unter ihrer Adresse. Das VPN trägt nur den Verkehr ins
Netz und das DNS des Telefons ([Namen](#names)); aller übrige Verkehr geht an
juist vorbei.

Das Telefon kann nicht:

- in mehr als einem Netz sein;
- [öffentliche Namen]({{< relref "docs/names" >}}) einschalten, sie lösen
  sich dort also öffentlich auf;
- einen [Subnet-Router]({{< relref "docs/subnets" >}}) nutzen oder
  [Exit-Node]({{< relref "docs/exit-nodes" >}}) sein, wohl aber einen nutzen;
- Geräte einladen, einen Admin-Schlüssel halten oder weiterleiten.
  Einladungen kommen vom Rechner eines Admins.

## Die App installieren

Jedes [Release](https://github.com/nning/juist/releases/latest) enthält die
App als `juist-android-arm64.apk`, für den Emulator
`juist-android-x86_64.apk`. Lade sie auf dem Telefon herunter und öffne sie;
Android fragt, ob der Browser Apps installieren darf.

Die App ist mit dem Release-Schlüssel von juist signiert. Der
SHA-256-Fingerabdruck ihres Zertifikats lautet:

```text
51:5C:14:80:41:8A:98:4A:8B:1A:E3:69:51:7A:2C:9F:7F:48:A2:19:41:0C:AE:E6:6F:B5:82:EF:EC:AB:E5:21
```

`apksigner verify --print-certs juist-android-arm64.apk` zeigt ihn an. Die
APK steht auch in `SHA256SUMS`
([Einen Download prüfen]({{< relref "docs/install" >}}#verifying-a-download)).

Wie du die App selbst baust, steht in
[android/README.md](https://github.com/nning/juist/blob/main/android/README.md).
Eine selbst gebaute App lässt sich nicht über ein Release installieren und
umgekehrt, weil ein anderer Schlüssel sie signiert.

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

Tippe auf ein Gerät, um Namen, Adressen, Rollen und den letzten Kontakt zu
sehen. **Ping** schickt ein Echo durch den Tunnel, das juist auf dem Gerät
beantwortet, auch wenn dessen Firewall Pings verwirft. **Im Browser öffnen**
öffnet `http://` mit seiner Adresse.

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

Der Schalter neben dem Zustand schaltet das VPN aus und ein. Solange es an
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
  kopiert das Log der App, das nur im Speicher liegt. Es nennt deine Geräte
  und Adressen; gib es nur jemandem, dem du vertraust.

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

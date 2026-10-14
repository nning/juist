---
title: Android
linkTitle: Android
description: Die Android-App von juist installieren, mit einem Telefon per QR-Code oder Code einem Netz beitreten und auf dem Telefon sehen, wie jedes Gerät erreicht wird.
lead: Mit der Android-App wird ein Telefon Mitglied eines Netzes. Es tritt per QR-Code oder Code der Einladung bei, erreicht die anderen Geräte unter ihren Adressen und zeigt, wie jedes davon erreicht wird.
---

## Was die App kann

Die App bringt juist auf ein Telefon mit Android 12 oder neuer. Das Telefon
tritt einem Netz als **Mitglied** ohne Rollen bei, also als Gerät, das die
anderen nur erreicht und von ihnen erreicht wird. Solange sein VPN an ist,
erreicht jede App auf dem Telefon die anderen Geräte unter ihren Adressen im
Netz.

Durch das VPN läuft nur der Verkehr zu den Adressen des Netzes. Der übrige
Verkehr des Telefons und sein DNS laufen wie bisher an juist vorbei.

Was das Telefon nicht kann:

- Es kann nur in einem Netz sein.
- Es löst keine Namen auf: `nas.home.juist` funktioniert dort nicht, nimm die
  Adresse des Geräts, etwa `198.18.36.2`.
- Es kann keinen [Subnet-Router]({{< relref "docs/subnets" >}}) nutzen und
  selbst keine [Exit-Node]({{< relref "docs/exit-nodes" >}}) sein, seinen
  Internetverkehr aber über eine schicken.
- Es kann keine Geräte einladen, keinen Admin-Schlüssel halten und keinen
  Verkehr für andere weiterleiten. Einladungen kommen von einem Admin, der
  `juist invite` auf einem Rechner aufruft.

## Die App installieren

Jedes [Release](https://github.com/nning/juist/releases/latest) enthält die
App als `juist-android-arm64.apk`. Lade sie auf dem Telefon herunter und
öffne sie. Android fragt dann, ob der Browser Apps installieren darf. Für den
Emulator nimmst du `juist-android-x86_64.apk`.

Die App ist mit dem Release-Schlüssel von juist signiert. Sein Zertifikat hat
den SHA-256-Fingerabdruck

```text
51:5C:14:80:41:8A:98:4A:8B:1A:E3:69:51:7A:2C:9F:7F:48:A2:19:41:0C:AE:E6:6F:B5:82:EF:EC:AB:E5:21
```

`apksigner verify --print-certs juist-android-arm64.apk` zeigt ihn an. Die APK
steht außerdem in `SHA256SUMS`, du kannst sie also prüfen, wie unter
[Den Download prüfen]({{< relref "docs/install" >}}#den-download-prüfen)
beschrieben.

## Aus dem Quellcode bauen

Du kannst die App auch selbst bauen, auf einem Rechner mit JDK 21, dem
Android-SDK mit Plattform 37.2 und dem NDK 29. Setz `ANDROID_HOME` auf das
SDK und `ANDROID_NDK_HOME` auf das NDK, falls es nicht im SDK liegt.

{{< step on="deinem Rechner" >}}
Bau die App im Quellcode:

```sh
make android
```

Das baut den Kern und die App nach `android/app/build/outputs/apk`, mit je
einem Release- und einem Debug-Build pro Prozessorarchitektur. Ein Telefon
braucht den Build für `arm64-v8a`, der Emulator den für `x86_64`.
{{< /step >}}
{{< step on="deinem Rechner" >}}
Installier sie auf einem Telefon, das per USB angeschlossen ist und
USB-Debugging an hat:

```sh
adb install android/app/build/outputs/apk/release/app-arm64-v8a-release.apk
```

Oder kopier die Datei aufs Telefon und öffne sie dort. Android fragt dann, ob
die App, mit der du sie öffnest, Apps installieren darf.
{{< /step >}}

Android installiert nur signierte Apps. Den Release-Build signierst du mit
deinem eigenen Schlüssel, den du einmal mit `keytool` aus dem JDK anlegst und
in `~/.gradle/gradle.properties` einträgst:

```sh
keytool -genkeypair -keystore ~/juist-app.jks -alias juist -keyalg RSA -keysize 4096 -validity 10000
```

```text
juist.signing.store=/home/du/juist-app.jks
juist.signing.storePassword=…
juist.signing.keyAlias=juist
juist.signing.keyPassword=…
```

Statt der beiden Passwörter kannst du `juist.signing.passwordFile=` auf eine
Datei mit dem Passwort setzen. Das geht bei einem PKCS12-Keystore, der nur ein
Passwort hat und den `keytool` standardmäßig anlegt.

Ohne diese Einträge bleibt der Release-Build unsigniert. Installier dann den
Debug-Build, `apk/debug/app-arm64-v8a-debug.apk`. Er ist eine eigene App,
`io.juist.debug`, und lässt sich neben einem Release-Build installieren.

Android installiert ein Update nur dann über die App, wenn derselbe Schlüssel
beide signiert hat. Ein Release lässt sich also nicht über eine selbst gebaute
App installieren und umgekehrt. Bleib bei einer der beiden: Deinstallierst du die App, um eine
mit einem anderen Schlüssel zu installieren, sind die Schlüssel des Telefons
weg, und es muss als neues Gerät wieder beitreten.

## Einem Netz beitreten

{{< screens >}}
welcome: Der erste Bildschirm: QR-Code scannen oder Code eintippen
joining_words: Die vier Wörter, die der Admin vergleicht
{{< /screens >}}

{{< step on="dem Gerät eines Admins" >}}
Starte eine Einladung in einem Terminal mit mindestens 59 Spalten, damit es
den QR-Code anzeigen kann:

```sh
juist invite
```
{{< /step >}}
{{< step on="dem Telefon" >}}
Öffne juist, tippe auf **QR-Code scannen** und richte die Kamera auf den
QR-Code. Android fragt einmal, ob juist die Kamera nutzen darf.

Oder tippe auf **Code eintippen** und gib den Code ein, etwa
`42-drumbeat-tolerance-glucose`. Die App ergänzt jedes Wort beim Tippen. Ein
Code funktioniert nur, wenn das Telefon im selben LAN ist wie das einladende
Gerät, denn die App sucht dieses Gerät, indem sie im LAN nachfragt, wie
`juist join` auch. Bist du woanders, scanne den QR-Code oder füge den Link in
dasselbe Feld ein.
{{< /step >}}
{{< step on="dem Telefon" >}}
Prüfe den Namen, den das Telefon im Netz haben wird. Die App schlägt einen
vor, der auf dem Namen des Telefons beruht, etwa `pixel-8`. Tippe auf
**Beitreten** und erlaube das VPN, wenn Android fragt.

Das Telefon zeigt dann vier Wörter in großer Schrift.
{{< /step >}}
{{< step on="dem Gerät eines Admins" >}}
Vergleiche sie mit den Wörtern, die die Einladung zeigt, und antworte mit
`y`, wenn sie übereinstimmen. Weichen sie ab, antworte mit `n` und brich auf
dem Telefon ab.
{{< /step >}}

Braucht das Netz die Stimmen mehrerer Admins, zeigt das Telefon
`Warte auf Zustimmung: 1 von 2 Stimmen`, bis die übrigen zugestimmt haben.
Danach zeigt es seinen Status. [Geräte einladen]({{< relref "docs/invites" >}})
erklärt Code, Link und Wörter.

## Der Statusbildschirm

{{< screens >}}
status: Das Netz, dieses Telefon und alles, worum du dich kümmern solltest
member: Ein Gerät, mit einem Ping durch den Tunnel
{{< /screens >}}

Die App zeigt, was `juist status`, `juist health` und `juist devices` auf einem
Rechner zeigen (siehe
[Status und Geräte]({{< relref "docs/status" >}})):

- Den Namen des Netzes und seinen Zustand, etwa **Verbunden**. Jeden
  anderen Zustand erklärt eine Zeile darunter.
- Alles, worum du dich kümmern solltest, etwa ein Gerät, das nicht antwortet,
  oder **Kein Gerät darf weiterleiten**: Ein Telefon im Mobilfunk braucht oft
  ein [Relay]({{< relref "docs/relays" >}}), um die anderen zu erreichen.
- Dieses Telefon: seinen Namen, seine IPv4- und IPv6-Adresse, die du zum
  Kopieren antippst, und seine Frische, also wann ein Voucher zuletzt
  bestätigt hat, dass es den aktuellen Stand des Netzes kennt.
- Jedes andere Gerät, mit der Art, wie es erreicht wird.

| Zustand | Bedeutung |
|---|---|
| Verbunden | das Telefon erreicht die Geräte des Netzes |
| Wartet auf Geräte | es gibt andere Geräte, aber noch keines hat sich gemeldet |
| Kein Tunnel steht | die Geräte sind bekannt, aber zu keinem fließt Verkehr |
| Eingeschränkt | kein Voucher hat in letzter Zeit bestätigt, dass der Stand des Telefons aktuell ist, also erreicht es nur Voucher |
| Entfernt | das Telefon gehört nicht mehr zum Netz |
| Abgewiesen | die Geräte des Netzes weisen das Telefon ab, wahrscheinlich wurde es entfernt |
| Getrennt | die Geschichte des Netzes hat sich gespalten, und alle Tunnel sind unterbrochen, bis ein Admin das klärt |
| Aus | das VPN ist aus |

Ein Gerät wird **Direkt** erreicht, **Über ein Relay** oder gerade nicht:
**Keine Antwort**, **Wird gesucht** (es wurde vielleicht neu gestartet oder
hat das Netz gewechselt), **Offline**, **Noch nicht gemeldet**,
**Noch nicht geprüft** oder **Veraltet** (darauf läuft ein älteres juist; bis
es aktualisiert ist, kommt ein Ping durch, andere Apps nicht).

Tippe auf ein Gerät, um seine Adressen, seine Rollen und seine letzte Meldung
zu sehen. **Ping** schickt ein Echo durch den Tunnel. juist auf dem Gerät
beantwortet es selbst, also kommt die Antwort auch dann, wenn die Firewall des
Geräts Pings verwirft.
**Im Browser öffnen** öffnet `http://` an seiner Adresse. Jede andere App
erreicht das Gerät unter denselben Adressen, etwa ein SSH-Client unter
`198.18.36.2`.

## Über eine Exit-Node

Hat das Netz [Exit-Nodes]({{< relref "docs/exit-nodes" >}}), listet der
Statusbildschirm sie unter **Internet**, neben **Direkt**. Wählst du eine, laufen
das Internet und das DNS des Telefons über sie, wie `juist exit use` auf einem
Rechner. Solange die gewählte Exit-Node nicht nutzbar ist, wird der
Internetverkehr des Telefons gesperrt statt an ihr vorbeigeschickt, und die App
sagt, warum. Mit **Direkt** geht er wieder ohne juist hinaus.

Stoppt juist, schickt Android den Verkehr des Telefons direkt hinaus. Soll er
stattdessen gesperrt werden, schalte für juist **Durchgehend aktives VPN** und
**Verbindungen ohne VPN blockieren** in den VPN-Einstellungen von Android ein.
Die App verlinkt diese Einstellungen.

## Das VPN aus- und einschalten

Der Schalter neben dem Zustand schaltet das VPN aus und ein. Solange es an
ist, zeigt eine Benachrichtigung den Zustand, mit der Aktion **Ausschalten**.

War das VPN an, schaltet juist es nach einem Neustart des Telefons oder einem
Update der App wieder ein. Auch die Android-Einstellung **Durchgehend aktives
VPN** in den VPN-Einstellungen funktioniert mit juist. Android betreibt immer
nur ein VPN: Eine andere VPN-App schaltet juist aus, und die App weist darauf
hin.

## Wenn das Telefon entfernt wird

Ein Admin entfernt das Telefon wie jedes andere Gerät, mit
`juist remove pixel-8` ([Geräte entfernen]({{< relref "docs/remove" >}})).
Die App zeigt dann **Entfernt**. Tippe auf **Netz vergessen**, um mit neuen
Schlüsseln neu anzufangen, und tritt dann mit einer neuen Einladung wieder
bei.

Willst du juist auf dem Telefon nicht mehr nutzen, lass es zuerst von einem
Admin entfernen und deinstalliere dann die App. Ein Telefon, auf dem die
App nur deinstalliert wurde, führt das Netz weiterhin als Mitglied.

## Datenschutz und Sicherheit

- Die Schlüssel des Telefons sind mit einem AES-256-Schlüssel versiegelt, den
  der Android-Keystore hält, im Sicherheitschip des Telefons, falls es einen
  hat. Dieser Schlüssel verlässt den Keystore nie, eine Kopie der Dateien der
  App lässt sich also auf keinem anderen Telefon öffnen.
- Nichts von juist landet in einem Backup oder auf einem neuen Telefon. Ein
  neues Telefon tritt mit einer eigenen Einladung bei.
- Die Kamera wird nur auf dem Scan-Bildschirm benutzt, um den QR-Code zu
  lesen, und nichts, was sie sieht, wird gespeichert oder verschickt.
- **Über juist** im Menü zeigt die Version der App und die Lizenzen der
  enthaltenen Komponenten. **Protokoll kopieren** kopiert das Protokoll der App, das
  sie nur im Speicher hält. Es nennt die Geräte und Adressen deines Netzes;
  gib es nur jemandem, dem du vertraust und der dir helfen soll.

## Fehlersuche

| Was du siehst | Was du tun kannst |
|---|---|
| **Nicht beigetreten** | Die Einladung ist vielleicht abgelaufen oder schon benutzt, oder das einladende Gerät ist nicht erreichbar. Starte eine neue Einladung. Ein Code funktioniert nur im selben LAN; scanne stattdessen den QR-Code. |
| **Kein Gerät darf weiterleiten** | Ein Admin vergibt `relay` an ein Gerät mit öffentlicher Adresse ([Relays]({{< relref "docs/relays" >}})). |
| **Eingeschränkt** | Das Telefon hat seit 48 Stunden nicht genug Voucher erreicht. Verbinde es mit einem Netz, in dem es sie erreichen kann. |
| **Zu wenige Voucher haben bestätigt: eingeschränkt in … Stunden** | Bring vorher einen Voucher wieder online. |
| **Abgewiesen** oder **Entfernt** | Das Telefon wurde entfernt. Vergiss das Netz und tritt mit einer neuen Einladung wieder bei. |
| `nas.home.juist` löst nicht auf | Das Telefon löst keine Namen auf; nimm die Adresse, die der Bildschirm des Geräts zeigt. |

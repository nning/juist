---
title: Ein Netz nur aus Telefonen
linkTitle: Nur Telefone
description: Ein Netz auf einem Android-Telefon gründen und die anderen einladen, ohne Rechner und ohne Server; sie treffen sich über Tailscales öffentliche DERP-Server, bis ein eigenes Gerät weiterleitet.
lead: Ein paar Telefone, kein Rechner, kein Server. Ein Telefon gründet das Netz und lädt die anderen ein, und sie erreichen einander im WLAN und über Mobilfunk, über Tailscales öffentliche DERP-Server, wo es direkt nicht geht.
---

## Was du bekommst

Jedes Telefon erreicht die anderen unter ihren Adressen im Netz, zu Hause,
unterwegs und über verschiedene Mobilfunknetze hinweg. Ein Telefon hält den
Admin-Schlüssel und nimmt die anderen auf oder entfernt sie, hinter seinem
Fingerabdruck. Ein entferntes Telefon erfährt davon, sobald es eines trifft,
das es weiß.

## Was du brauchst

- Android 12 oder neuer auf jedem Telefon, mit der [App]({{< relref "docs/android" >}}).
- Eine Displaysperre auf dem Telefon, das das Netz gründet: Sie schützt den
  Admin-Schlüssel.

## Einrichten

{{< step on="dem ersten Telefon" >}}
Tippe auf **Netz anlegen**, gib dem Netz und dem Telefon einen Namen und
bestätige mit Fingerabdruck oder Displaysperre.

Die App zeigt dann einmal die Break-Glass-Zeile des Netzes: Bewahre sie
sicher auf, getrennt vom Telefon, für den Fall, dass das Netz einmal beendet
werden muss. Sie bietet auch eine Sicherung des Admin-Schlüssels an, die du
überspringen kannst, wie unter [Android]({{< relref "docs/android" >}})
beschrieben.
{{< /step >}}

{{< step on="dem ersten Telefon" >}}
Tippe unter den Geräten auf **Gerät einladen**. Die App zeigt einen QR-Code.
{{< /step >}}

{{< step on="jedem anderen Telefon" >}}
Scanne den QR-Code mit der App. Beide Telefone zeigen vier Wörter; stimmen
sie überein, tippe auf dem ersten Telefon auf **Dieselben Wörter** und
bestätige mit dem Fingerabdruck.
{{< /step >}}

## Darauf achten

- **Tailscales Server sehen, wer mit wem redet.** Telefone im Mobilfunk
  erreichen einander selten direkt, und kein Telefon kann für die anderen
  weiterleiten. Deshalb nutzt das Netz von Anfang an Tailscales öffentliche
  DERP-Server. Sie tragen nur verschlüsselten WireGuard-Verkehr, sehen aber
  die öffentliche Adresse jedes Telefons und welche Telefone wann wie viel
  miteinander austauschen ([Relays]({{< relref "docs/relays" >}}#public-derp)).
  Ein Tailscale-Konto brauchst du nicht.
- **Der Admin-Schlüssel liegt auf einem Telefon.** Geht es ohne Sicherung
  verloren, lässt sich das Netz nicht mehr ändern: kein Gerät mehr
  aufnehmen, keines entfernen. Die Break-Glass-Zeile beendet es nur von
  einem Rechner aus, der schon Mitglied ist, und das ist kein Telefon: Nimm
  früh einen Laptop auf, oder bewahre die Sicherung des Schlüssels auf.
- **Die Frische bleibt ungeprüft**, weil kein Telefon für die anderen
  bürgt: Ein entferntes Telefon funktioniert weiter mit denen, die von
  seiner Entfernung noch nichts wissen.

## Ohne Tailscales Server

Sobald ein Gerät von dir mit öffentlicher Adresse weiterleitet, braucht das
Netz Tailscales Server nicht mehr. Abschalten kannst du sie auf einem
Laptop, denn die App hat keinen Schalter dafür.

{{< step on="dem ersten Telefon" >}}
Lade den Laptop ein: **Gerät einladen**, dann den Link teilen.
{{< /step >}}

{{< step on="laptop" >}}
[Installiere juist]({{< relref "docs/install" >}}) und tritt mit dem Link
bei:

```sh
sudo juist join 'juist:…'
```

Vergleiche dann die vier Wörter mit denen auf dem Telefon und nimm ihn dort
auf.
{{< /step >}}

{{< step on="dem ersten Telefon" >}}
Tippe im Menü des Statusbildschirms auf **Admin-Schlüssel sichern** und
kopiere die Zeile in einen Passwortmanager, oder speichere sie als Datei,
mit einem Passwort versiegelt.
{{< /step >}}

{{< step on="laptop" >}}
Importiere den Admin-Schlüssel aus der Zeile oder der Datei, unter einem
Namen deiner Wahl:

```sh
pass show juist/home | juist admins import alice@home
```

oder `juist admins import alice@home < juist-admin-home.txt`, die Datei,
die die App gespeichert hat; das fragt nach ihrem Passwort. Der Laptop hält
nun eine Kopie des Schlüssels vom Telefon
([Admin-Schlüssel]({{< relref "docs/keys" >}})).
{{< /step >}}

{{< step on="vps" as="dem Relay" >}}
Richte ein Gerät mit öffentlicher Adresse als Relay ein, etwa einen kleinen
VPS, wie unter [Relays]({{< relref "docs/relays" >}}#ein-relay-einrichten)
beschrieben: beitreten, die Ports öffnen und auf dem Laptop `juist grant vps
relay`. Gib ihm auch einen öffentlichen Namen auf 443
([Ein Relay auf 443]({{< relref "docs/relays" >}}#ein-relay-auf-443)): Bisher
bedienten Tailscales Server Telefone in WLANs, die nichts als HTTPS
hinauslassen, ohne sie tut das nur dieser Name.
{{< /step >}}

{{< step on="laptop" >}}
Schalte Tailscales Server ab:

```sh
juist network derp off
```

`juist status` zählt den VPS dann in der Zeile `Relays` und nennt
Tailscales Server nicht mehr.
{{< /step >}}

Ein Laptop hinter NAT, wie zu Hause, leitet für niemanden weiter: Schaltest
du Tailscales Server ab, bevor ein Gerät mit öffentlicher Adresse
weiterleitet, finden Telefone im Mobilfunk, die einander nicht direkt
erreichen, keinen Weg mehr zueinander. `juist network derp on`
schaltet sie wieder ein.

Voucher begrenzen auf 48 Stunden, wie lange ein entferntes Telefon noch mit
den anderen funktioniert. Dafür taugen Geräte, die immer laufen, am besten
zwei an verschiedenen Orten
([Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)). Ein
Laptop oder Telefon, das oft aus ist, taugt schlecht dafür, und ein Relay als
Voucher könnte, solange ein Voucher genügt, ein Gerät, das es abschneidet,
frisch halten, wovor `juist grant` warnt.

## Weiterlesen

- [Android]({{< relref "docs/android" >}}): die App, der Admin-Schlüssel und
  seine Sicherung
- [Ohne eigenes Relay]({{< relref "docs/relays" >}}#public-derp): was
  Tailscales Server sehen
- [Admin-Schlüssel]({{< relref "docs/keys" >}}): die Break-Glass-Zeile und
  Schlüssel auf mehreren Geräten

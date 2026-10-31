---
title: Netze, die nur HTTPS durchlassen
linkTitle: Nur HTTPS
description: Dein Netz aus einem Hotel-, Firmen- oder Schulnetz erreichen, das nichts als HTTPS hinauslässt, über deine Relays auf Port 443 und über einen Proxy, falls es einen gibt.
lead: Manche Netze lassen nichts als HTTPS hinaus, und manche prüfen, ob der Verkehr wie HTTPS aussieht. Ein Gerät in einem solchen Netz erreicht die anderen über deine Relays auf Port 443, wie ein HTTPS-Client unter vielen.
---

## So funktioniert es

Im Netz eines Hotels, einer Firma oder einer Schule kommt oft nur TCP zu
Port 443 hinaus. WireGuard, die Pfadsuche und der übliche Port 41645 des
Relays sind gesperrt.

Der Weg hinaus ist ein [Relay]({{< relref "docs/relays" >}}), das einen
öffentlichen Namen auf Port 443 bedient. Jedes Gerät erfährt diesen Namen.
Erreicht ein Gerät den üblichen Port des Relays nicht, weicht es von selbst
auf den Namen aus; auf dem Gerät musst du nichts einrichten.

Ein Relay auf 443 genügt: Geräte, die andere Relays nutzen, halten eine
Verbindung zu ihm, also erreicht es auch sie. Handys, die Akku sparen, halten
keine und werden erreicht, sobald sie wieder senden. Ist der
[Ingress]({{< relref "docs/publishing" >}}) des Netzes auch Relay, bedient er
`relay.DOMAIN` auf 443 von selbst.

Ein Netz, das den Verkehr prüft und alles blockiert oder meldet, was kein
HTTPS ist, verlangt mehr. Mit `juist set --https-only` schickt ein Gerät nur
noch TLS an die Namen der Relays auf Port 443, dazu DNS-Anfragen nach diesen
Namen. Es schickt kein WireGuard über UDP, sucht keine Pfade und nicht im LAN
und nutzt weder den öffentlichen DHT noch STUN-Server. Jedes Paket läuft über
ein Relay.

## Einrichten

{{< step on="dem Relay" >}}
Sofern das Relay des Ingress nicht schon einen bedient, gib einem Relay einen
öffentlichen Namen auf Port 443, wie unter
[Relays]({{< relref "docs/relays" >}}) beschrieben:

```sh
sudo juist set --relay-name relay.example.org
```
{{< /step >}}

{{< step on="laptop" as="dem Gerät im Hotel" >}}
Ab jetzt nur noch HTTPS senden:

```sh
sudo juist set --https-only
```

Die Ausgabe lautet `https only`. `juist status` zeigt dann, über welche Relays
der Verkehr läuft:

```console
  HTTPS         only, by relay.example.org
```
{{< /step >}}

Um von dort aus einem Netz beizutreten, setze die Option vor `juist join`
und nimm den Einladungslink, nicht den Code. Der Link nennt die Relays auf
443, etwa `r=relay.example.org`; ein Code braucht das LAN, das der
Nur-HTTPS-Modus nicht durchsucht.

```sh
sudo juist set --https-only
sudo juist join 'juist:…'
```

Zurück in einem offenen Netz lässt `sudo juist set --https-only=false` die
Tunnel wieder direkt laufen.

## Über einen Proxy

Manche Firmennetze lassen Verkehr nur über ihren HTTP-Proxy hinaus. Gib juist
den Proxy an, mit Benutzername und Passwort, falls er welche verlangt:

```sh
sudo juist set --https-only --proxy -
```

juist fragt dann nach der URL, etwa
`http://user:password@proxy.example.com:3128`, und zeigt sie beim Tippen
nicht an. Auf der Kommandozeile könnte jeder Benutzer des Geräts das Passwort
lesen. Für einen Proxy ohne Passwort genügt
`--proxy http://proxy.example.com:3128`.

juist bittet den Proxy nur um `CONNECT relay.example.org:443`, und der Proxy
löst den Namen selbst auf. Das Gerät braucht dann also kein eigenes DNS. Ohne
`--proxy` nimmt juistd das `HTTPS_PROXY` aus seiner Umgebung, und
`--proxy ""` kehrt dazu zurück. `juist status` zeigt den Proxy ohne sein
Passwort.

## Gut zu wissen

- Jedes Paket läuft über ein Relay, das damit die Geschwindigkeit begrenzt.
  Die TCP-Verbindungen des Tunnels laufen dann in TCP, das sich von
  Paketverlusten nur langsam erholt. Zwei Relays an verschiedenen Orten halten
  ein Gerät erreichbar, wenn eines ausfällt.
- Das Zertifikat des Relays wird gegen die Zertifizierungsstellen geprüft,
  denen das System vertraut, wie ein Browser es tut. Ein Gerät nutzt den Namen
  eines Relays erst, wenn der Server unter diesem Namen bestätigt, dass er
  dieses Relay ist. Eine Firma, die TLS aufbricht, sieht nicht mehr als das
  Relay: WireGuard verschlüsselt von Ende zu Ende. Sie sieht also, welche
  Geräte miteinander sprechen, aber nicht, was sie sagen.
- Der Nur-HTTPS-Modus verbirgt juist nicht vor einem Zensor, der Server
  abtastet oder TLS am Fingerabdruck erkennt. Wer den Namen des Relays
  abfragt, findet ein Relay, und der TLS-Handshake ist der eines Go-Programms,
  nicht eines Browsers.
- Die Android-App hat keine Einstellung für den Nur-HTTPS-Modus. Sie weicht
  aber von selbst auf den Namen eines Relays auf 443 aus, wo UDP und der Port
  des Relays gesperrt sind.

## Fehlersuche

| Was du siehst | Was zu tun ist |
|---|---|
| `juist status`: `HTTPS  only, and no relay on 443` | gib einem Relay einen öffentlichen Namen: `sudo juist set --relay-name NAME` auf ihm |
| `juist health`: `warning: no relay on 443/tcp` | dasselbe |
| `juist health`: `no answer from …: offline, or at no relay on 443` | das Gerät ist offline oder erreicht kein Relay mit Namen |
| `juist health`: `no tunnel traffic from … through the relays on 443` | prüfe die Namen der Relays im DNS, und ob Port 443 sie erreicht |
| `juist health`: `warning: … not at the relay on …, the one this device reaches it at` | das Gerät läuft, hält dort aber keine Verbindung: es spart Akku und wird erreicht, sobald es sendet, oder es läuft mit einem älteren juist |
| `juist health`: `no answer from …: not at the relay on …` | das Gerät ist offline oder hält dort keine Verbindung; sobald feststeht, dass es offline ist, verschwindet die Zeile |

Meldet der Beitritt `the invite link names no relay on 443`, brauchst du einen
neuen Einladungslink, erstellt, nachdem ein Relay einen Namen auf 443 bedient.

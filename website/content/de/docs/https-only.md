---
title: Netze, die nur HTTPS durchlassen
linkTitle: Nur HTTPS
description: Dein Netz aus einem Hotel-, Firmen- oder Schulnetz erreichen, das nichts als HTTPS hinauslässt, über deine Relays auf 443 und über einen Proxy, wo es einen gibt.
lead: Manche Netze lassen nichts als HTTPS hinaus, und manche sortieren, was durchgeht, nach seinem Aussehen. Ein Gerät dort erreicht die anderen über deine Relays auf Port 443, als ein HTTPS-Client unter vielen.
---

## Was es ist

Im Netz eines Hotels, einer Firma oder einer Schule kommt oft nur TCP zu
Port 443 hinaus. WireGuard, die Pfadsuche und der eigene Port 41645 des
Relays nicht.

Ein [Relay]({{< relref "docs/relays" >}}), das einen öffentlichen Namen auf
443 bedient, ist der Weg hinaus. Jedes Gerät erfährt den Namen, und eines, das
den eigenen Port des Relays nicht erreicht, weicht von selbst auf den Namen
aus. Dafür ist auf dem Gerät nichts einzurichten.

Ein Netz, das genauer hinsieht und blockiert oder meldet, was kein HTTPS ist,
braucht mehr: Mit `juist set --https-only` schickt ein Gerät nichts als TLS
an die Namen der Relays auf 443 und DNS-Anfragen nach diesen Namen. Kein
WireGuard über UDP, keine Pfadsuche, keine Suche im LAN, keine öffentliche
DHT und kein STUN-Server. Jedes Paket läuft dann über ein Relay.

## Einrichten

{{< step on="dem Relay" >}}
Gib einem Relay einen öffentlichen Namen auf 443, wie unter
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

Es gibt `https only` aus. `juist status` nennt dann die Relays, über die es
läuft:

```console
  HTTPS         only, by relay.example.org
```
{{< /step >}}

Um von dort aus einem Netz beizutreten, setze es vor `juist join` und nimm
den Link der Einladung: Er nennt die Relays auf 443, als `r=relay.example.org`.
Ein eingetippter Code wird im LAN gesucht, das ein Gerät mit nur HTTPS nicht
durchsucht.

```sh
sudo juist set --https-only
sudo juist join 'juist:…'
```

Zurück in einem offenen Netz lässt `sudo juist set --https-only=false` die
Tunnel wieder direkt laufen.

## Über einen Proxy

Ein Firmennetz lässt vielleicht nichts hinaus außer über seinen HTTP-Proxy.
Nenne den Proxy, mit Benutzer und Passwort, wo er danach fragt:

```sh
sudo juist set --https-only --proxy http://user:password@proxy.example.com:3128
```

Der Proxy wird nur um `CONNECT relay.example.org:443` gebeten und löst den
Namen selbst auf; das Gerät braucht dann kein eigenes DNS. Ohne `--proxy`
nimmt juistd das `HTTPS_PROXY` seiner Umgebung, und `--proxy ""` kehrt dazu
zurück. `juist status` zeigt den Proxy ohne sein Passwort.

## Gut zu wissen

- Jedes Paket läuft über ein Relay, mit dessen Geschwindigkeit, und TCP
  trägt das TCP des Tunnels, das sich von Verlusten nur langsam erholt. Zwei
  Relays an verschiedenen Orten halten ein Gerät erreichbar, wenn eines
  ausfällt.
- Das Zertifikat des Relays wird gegen die Zertifizierungsstellen geprüft,
  denen das System vertraut, wie ein Browser es tut. Eine Firma, die TLS
  aufbricht, sieht nicht mehr als das Relay: WireGuard verschlüsselt von Ende
  zu Ende, sie sieht also, welche Geräte miteinander sprechen, nicht was.
- Es verbirgt juist nicht vor einem Zensor, der Server abtastet oder TLS am
  Fingerabdruck erkennt: Wer den Namen des Relays abfragt, findet ein Relay,
  und der TLS-Handshake ist der eines Go-Programms, nicht eines Browsers.
- Die Android-App hat dafür noch keinen Schalter. Sie weicht von selbst auf
  den Namen eines Relays auf 443 aus, wo UDP und der Port des Relays gesperrt
  sind.

## Wenn etwas nicht klappt

| `juist status` sagt | Was zu tun ist |
|---|---|
| `HTTPS  only, and no relay on 443` | gib einem Relay einen öffentlichen Namen: `sudo juist set --relay-name NAME` auf ihm |
| `warning: no relay on 443/tcp` | dasselbe |
| `no answer from …: offline, or at no relay on 443` | das Gerät ist offline oder erreicht kein Relay mit Namen |
| `no tunnel traffic from … through the relays on 443` | prüfe die Namen der Relays im DNS, und dass 443 sie erreicht |

Ein Beitritt, der `the invite link names no relay on 443` meldet, braucht
einen neuen Link, erstellt, sobald ein Relay einen Namen auf 443 bedient.

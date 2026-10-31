---
title: Vom Laptop aus teilen
linkTitle: Vom Laptop aus teilen
description: Eine Datei, ein Verzeichnis oder den Webserver, an dem du gerade arbeitest, mit einem Befehl ins Internet stellen, unter dem eigenen Namen deines Laptops, wie mit ngrok oder cloudflared.
lead: Eine Datei für einen Kunden, ein Ordner mit Fotos, die Web-App, an der du gerade sitzt. Ein Befehl stellt sie unter https://laptop.example.org ins Internet, so lange du willst, ohne Konto bei einem Tunnel-Anbieter.
---

## Was du bekommst

`juist share` stellt eine Datei oder ein Verzeichnis unter einen zufälligen
Link auf dem eigenen Namen deines Laptops, und `juist publish PORT` macht das
Gleiche mit einem Webserver, der auf dem Laptop läuft. Das ist, was ngrok
oder ein Quick Tunnel von cloudflared tun, aber unter deiner eigenen Domain
und über deinen eigenen Ingress. TLS endet erst auf dem Laptop, der Ingress
sieht den Inhalt also nie.

Eine Freigabe endet mit ihrem Befehl, nach Ablauf von `--for` oder
spätestens nach sieben Tagen.

## Was du brauchst

- Ein Netz mit einer Domain und einem Ingress, also einem Gerät mit
  öffentlicher Adresse, das Verbindungen weiterreicht.
  [Dienste veröffentlichen]({{< relref "docs/publishing" >}}#setting-it-up)
  richtet beides in seinen ersten drei Schritten einmal ein.
- Den Laptop unter Linux oder FreeBSD.

## Einrichten

{{< step on="dem Gerät eines Admins" >}}
Erlaube dem Laptop, unter seinem eigenen Namen zu veröffentlichen, ohne
jedes Mal einen Admin zu fragen:

```sh
juist grant laptop publish
```
{{< /step >}}

{{< step on="laptop" >}}
Teile ein Verzeichnis oder den Webserver auf Port 8000:

```sh
juist share ~/photos/2026
juist publish 8000 --for 2h
```

Der erste Befehl gibt seinen Link aus, `https://laptop.example.org/…/` mit
einem zufälligen Pfad, und läuft bis Strg-C. Der zweite gibt
`publishing 127.0.0.1:8000 at https://laptop.example.org, until …` aus.
Mit `-b` läuft eine Freigabe im Hintergrund weiter, bis `juist share --stop`
oder `--for` sie beendet.
{{< /step >}}

{{< step on="laptop" >}}
Sieh nach, was geteilt ist, und beende es:

```sh
juist share
juist share --stop ~/photos/2026
```
{{< /step >}}

## Darauf achten

- **Eine Freigabe ist für jeden offen, der den Link hat.** Der zufällige
  Pfad verhindert, dass ihn jemand errät; jeder andere Pfad antwortet mit 404.
- **`juist publish PORT` hat keinen zufälligen Pfad.** Es beantwortet jeden
  Pfad unter `https://laptop.example.org`, und der Name steht in den
  öffentlichen Zertifikatslogs der CA. Rechne also mit Scannern. Veröffentliche
  so nur einen Server, der ins Internet darf, und gib ihm ein `--for` mit.
- **Der Laptop ist ein vollwertiges Mitglied.** Bricht jemand in den
  Webserver ein, den du veröffentlichst, erreicht er von dort dein Netz. Für
  einen Server, der länger läuft, nimm ein
  [Service-Mitglied]({{< relref "docs/service-member" >}}).
- **Die Freigabe braucht den Laptop.** Verschwindet er, enden seine
  Freigaben spätestens zehn Minuten später.

## Weiterlesen

- [Sofort teilen]({{< relref "docs/sharing" >}}): Pfade,
  Verzeichnisse als ZIP, Grenzen
- [Dienste veröffentlichen]({{< relref "docs/publishing" >}}): die Domain und
  der Ingress

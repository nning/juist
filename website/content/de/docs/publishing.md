---
title: Dienste veröffentlichen
linkTitle: Dienste veröffentlichen
description: Einen Dienst auf einem deiner Geräte, etwa auf dem NAS zu Hause, unter einem Namen aus dem Internet erreichbar machen.
lead: Ein Dienst auf einem Mitglied, etwa auf dem NAS zu Hause, wird unter einem Namen aus dem Internet erreichbar. Ein Gerät mit öffentlicher Adresse leitet die Verbindungen weiter, und TLS endet erst beim Mitglied.
status: [Linux, FreeBSD]
---

## So funktioniert es

Angenommen, auf deinem NAS läuft ein Dokumentenserver, und du willst ihn aus
jedem Browser unter `docs.example.org` öffnen. Dein Router öffnet dafür keinen
Port, und seine Adresse steht in keinem öffentlichen Eintrag.

Ein **Ingress** ist ein Mitglied mit öffentlicher Adresse, etwa ein kleiner
VPS, dem ein Admin die Rolle `ingress` gegeben hat. Er nimmt Verbindungen auf
Port 443 an, liest den angefragten Namen und leitet die Verbindung durch den
Tunnel an das Mitglied weiter, das den Namen veröffentlicht.

{{< flow publish >}}

Der Ingress entschlüsselt kein TLS. TLS endet auf dem NAS, mit einem
Zertifikat von Let's Encrypt, und das NAS reicht die Verbindung an den Dienst
weiter. Ein Ingress bedient alle Namen des Netzes.

Jede Art zu veröffentlichen braucht eine Domain und einen Ingress. Die
Schritte 1 bis 3 unten richten beides einmal ein.

| Was | Wo |
|---|---|
| einen Webdienst auf einem Mitglied | [Einrichten](#setting-it-up) |
| einen Server, dem du in deinem Netz nicht traust | [Service-Mitglieder]({{< relref "docs/service-member" >}}) |
| einen Namen, den nur Mitglieder öffnen können | [Namen nur für Mitglieder]({{< relref "docs/members-only" >}}) |
| einen Spieleserver oder einen anderen Dienst ohne TLS | [TCP-Dienste]({{< relref "docs/tcp-services" >}}) |
| eine Datei, ein Verzeichnis oder einen lokalen Webserver, sofort | [Teilen]({{< relref "docs/sharing" >}}) |
| eine Übersicht über die Geräte des Netzes | [Statusseite](#status-page) |

## Einrichten {#setting-it-up}

{{< step on="dem Gerät eines Admins" >}}
Leg die Domain des Netzes fest und gib dem VPS die Rolle:

```sh
juist network domain example.org
juist grant vps ingress
```

`juist invite vps --ingress` nimmt ein neues Gerät gleich als Ingress auf.
{{< /step >}}

{{< step on="der Website deines DNS-Anbieters" >}}
Lass `*.example.org` auf die öffentliche Adresse des VPS zeigen, oder nur
`docs.example.org`.
{{< /step >}}

{{< step on="vps" as="dem Ingress" >}}
```sh
juist ingress serve
```

Der Befehl fragt einmal nach sudo und startet den Dienst `juist-ingress`.
Unter Linux öffnet er 443 (TCP und UDP) und 80 in firewalld oder ufw. Unter
FreeBSD entscheiden die pf-Regeln des Hosts. Port 80 leitet nur auf https um.
{{< /step >}}

{{< step on="nas" as="dem Ziel" >}}
Der [Operator]({{< relref "docs/operator" >}}) des NAS veröffentlicht den
Namen und sagt, wohin die Verbindung geht:

```sh
juist publish add docs 127.0.0.1:8080
```

juist holt über den Ingress ein Zertifikat und beendet TLS auf dem NAS. Der
Befehl gibt `nas: publishes docs.example.org:443`, `serving docs.example.org`
und `ending TLS for docs.example.org to 127.0.0.1:8080` aus, danach den
[CAA-Eintrag](#protecting-the-certificate) des Namens. Beim ersten Mal warnt
er außerdem:
`warning: a server published from this device reaches the network and its LAN once compromised`.

Veröffentlichen ist eine Änderung, die nur Admins machen können. Hat das NAS
keinen Admin-Schlüssel, gibt der Befehl
`docs.example.org goes to 127.0.0.1:8080 once published on this device` aus,
dazu den Befehl für einen Admin: `juist publish add nas docs.example.org`.
Braucht eine Änderung mehr als einen Admin, wartet sie auf die anderen
([wie Änderungen bestätigt werden]({{< relref "docs/network-changes" >}})).
{{< /step >}}

`juist grant` und `juist publish add` nennen den nächsten Schritt und das
Gerät, auf dem er läuft. Führst du sie dort als dessen Operator aus,
erledigen sie diesen Schritt gleich mit.

{{< note danger >}}
Bricht jemand in einen Server ein, den ein vollwertiges Mitglied
veröffentlicht, erreicht er das Netz und das LAN des Mitglieds. Veröffentliche
von einem vollwertigen Mitglied nur, was du ohnehin ins Internet stellen
würdest. Für alles andere gibt es
[Service-Mitglieder]({{< relref "docs/service-member" >}}).
{{< /note >}}

## Das Zertifikat schützen {#protecting-the-certificate}

Wer den Ingress kontrolliert, kann ein Zertifikat für deine Namen bekommen und
öffentliche Clients abfangen. Das trifft auch Mitglieder, die einen Namen über
den Ingress erreichen: auf einem anderen Port als 443, hinter `--proxy` oder
auf Geräten, die die Namen des Netzes nicht auflösen. Mitglieder, die einen
Namen auf 443 zu seinem Gerät auflösen, verbinden sich direkt.

Ein **CAA-Eintrag** schließt diese Lücke. Dieser DNS-Eintrag erlaubt nur dem
ACME-Konto des Ziels, Zertifikate für den Namen zu bekommen. Trag ihn bei
deinem DNS-Anbieter ein:

- `juist publish add NAME HOST:PORT` gibt ihn aus.
- `juist publish serve`, vom Operator des Geräts ausgeführt, gibt ihn erneut
  aus.
- Das Log des Terminators enthält ihn auch: `journalctl -u juist-serve`, unter
  FreeBSD `/var/log/juist-serve.log`. Ein Service-Mitglied schreibt ihn in
  sein eigenes Log.

Ein CAA-Eintrag auf der Domain gilt für jeden Namen darunter ohne eigenen.
Gib den Namen jedes Geräts deshalb einen eigenen Eintrag.

## Namen und DNS-Einträge

- Ein Name ist ein Label unter der Domain, etwa `docs.example.org`, oder die
  Domain selbst, ausgeschrieben: `juist publish add nas example.org`. Ein
  Gerät veröffentlicht höchstens 16 Namen.
- Nur ein Gerät kann die Domain selbst veröffentlichen. Die Domain braucht
  eigene A- und AAAA-Einträge auf den Ingress, weil `*.example.org` sie nicht
  abdeckt.
- Ein Name mit einem eigenen Eintrag, etwa dem CAA- oder HTTPS-Eintrag, den
  juist ausgibt, bekommt keine Adresse mehr von `*.example.org`. Gib ihm auch
  eigene A- und AAAA-Einträge.
- Mitglieder unter Linux und FreeBSD lösen die Domain über juistd auf. Ein
  Name auf 443 oder ein geteilter Name zeigt auf sein Gerät, solange es
  erreichbar ist. Mitglieder erreichen ihn dann direkt durch den Tunnel.
  DNSSEC ist für die Domain auf Mitgliedern aus
  ([Namen]({{< relref "docs/names" >}})).
- `http://NAME` erreicht Port 80 auf dem Gerät, wo juist auf https umleitet.
  Lauscht dort ein anderes Programm auf allen Adressen, antwortet es statt
  juist, und `juist health` warnt.

## HTTP/3 {#http3}

Für einen Namen, dessen TLS juist beendet und dessen Dienst HTTP spricht,
können Browser HTTP/3 nutzen, also QUIC auf 443/udp:

```sh
juist publish add docs 127.0.0.1:8080 --http3
```

Der Befehl gibt einen DNS-Eintrag zum Eintragen aus:
`docs.example.org. HTTPS 1 . alpn="h3,h2"`. Mit ihm nutzen Browser HTTP/3 ab
der ersten Anfrage, ohne ihn ab der zweiten, sobald der `Alt-Svc`-Header von
juist es ihnen gesagt hat. Ist 443/udp unterwegs gesperrt, bleiben Browser bei
HTTP/2 über TCP.

- Mit `--http3` leitet juist das HTTP des Dienstes als Proxy weiter und
  bietet auch HTTP/2 an. Der Dienst sieht den ursprünglichen Host jeder
  Anfrage und keine Proxy-Header. Mit zusätzlich `--http2` spricht juist h2c
  mit dem Dienst.
- WebSockets bleiben bei HTTP/1.1 über TCP.
- Ein Client, dessen Adresse wechselt, etwa ein Handy vom WLAN ins
  Mobilnetz, verbindet sich neu.
- Ein Service-Mitglied bietet HTTP/3 mit `juistd --serve NAME=ADDR --http3`
  an. Die Statusseite bietet es immer an. Geteiltes läuft nur über TCP.

## Weitere Optionen

- Ein Dienst kann TLS selbst beenden, mit eigenem Zertifikat. Ein Admin
  veröffentlicht ihn mit `juist publish add nas docs`, auf Port 443, wenn du
  keinen anderen angibst, und der Operator des NAS stimmt mit
  `juist publish serve` zu.
- `--proxy` schickt dem Dienst die Adresse des Clients in einem
  PROXY-Protokoll-v2-Header, auch über HTTP/3. Mitglieder erreichen den Namen
  dann über den Ingress.
- `--http2` bietet Clients HTTP/2 an, für einen Dienst, der es ohne TLS
  annimmt (h2c). Ein Dienst, der nur HTTP/1.1 spricht, scheitert damit.

## Statusseite {#status-page}

Ein Gerät kann die Statusseite des Netzes unter einem veröffentlichten Namen
anbieten:

```sh
juist publish status-page status                # unter https://status.example.org/
juist publish status-page status --public all   # alle sehen alles
```

Mitglieder sehen alles: die Geräte mit Adressen, Rollen und Schema, wie das
anbietende Gerät jedes erreicht, die veröffentlichten und geteilten Namen, was
Aufmerksamkeit braucht, und die neuesten Änderungen im Log. Alle anderen sehen,
was `--public` erlaubt, und nie einen Namen nur für Mitglieder:

| `--public` | Was Nicht-Mitglieder sehen |
|---|---|
| `none` | nichts: die Seite antwortet mit 404 |
| `services`, der Standard | die veröffentlichten und geteilten Namen, und ob sie laufen |
| `network` | alles außer den Änderungen |
| `all` | alles |

- Die Seite erkennt ein Mitglied an der Overlay-Adresse, von der seine
  Verbindung kommt. Wer über den Ingress kommt, zählt als Öffentlichkeit.
- Erreichbarkeit und Warnungen sieht das anbietende Gerät. Biete die Seite
  deshalb auf einem Gerät an, das immer läuft. Ein Ingress kann sie nicht
  anbieten.
- Führ den Befehl mit einem anderen `--public` erneut aus, um es zu ändern.
  `juist publish remove status` nimmt die Seite vom Netz.
- Ein Service-Mitglied bietet sie mit `--serve status=status-page:all` an.

{{< note caution >}}
Mit `--public network` oder `all` sieht jeder, der die Adresse kennt, Namen,
Overlay-Adressen und Rollen deiner Geräte. Mit `all` sieht er auch, wer welche
Änderung bestätigt hat.
{{< /note >}}

## Veröffentlichte Namen verwalten

- `juist publish` listet die veröffentlichten Namen auf, und wohin dieses
  Gerät seine eigenen weiterleitet.
- `juist publish remove docs` beendet das Veröffentlichen eines Namens auf
  diesem Gerät, `juist publish remove nas docs` auf einem anderen.
- `juist publish serve --stop` beendet das Bedienen, behält aber, wohin die
  Namen gehen. `juist ingress serve --stop` beendet den Ingress.
- `juist network domain off` wird abgelehnt, solange Geräte Namen unter der
  Domain veröffentlichen. Die Fehlermeldung nennt das `juist publish remove`,
  das zuerst nötig ist.
- Ingress und das TLS von juist laufen unter Linux und FreeBSD, für das
  Standardnetz des Geräts.

## Der Ingress

- Ein Ingress hat keine weitere Rolle: Er ist weder Voucher noch Exit-Node und
  routet kein Subnetz. Er kann nicht teilen und veröffentlicht nichts auf 80,
  443 oder einem per TCP veröffentlichten Port, weil er diese Ports selbst
  belegt. `juist grant` nennt die Rolle, die im Weg ist.
- Mitglieder nehmen von einem Ingress nur an: Verbindungen zu den Ports, die
  sie veröffentlichen und bedienen, den Log-Abgleich und Antworten auf ihre
  eigenen Verbindungen. Alles andere verwerfen sie.
- Er läuft als eigener Benutzer `juist-ingress`, hält keinen Schlüssel des
  Netzes und kann juistd nur fragen, was veröffentlicht ist.
- Ein Ingress mit veraltetem Blick auf das Netz bedient nichts. Antwortet sein
  juistd nicht mehr, gehen die Namen innerhalb von 15 Sekunden vom Netz.
- Er schreibt eine Logzeile pro Verbindung: Adresse des Clients, Name,
  Ergebnis, Bytes und Dauer. Siehe `journalctl -u juist-ingress`, unter
  FreeBSD `/var/log/juist-ingress.log`.
- `juist revoke vps ingress` macht das Gerät wieder zu einem gewöhnlichen
  Mitglied, mit einer Warnung. Ein womöglich kompromittiertes Gerät entfernst
  du stattdessen mit `juist remove`. Führ danach `juist ingress serve --stop`
  darauf aus.

## Grenzen

- Ein Ingress leitet bis zu 16384 Verbindungen gleichzeitig weiter: 256 von
  einer IPv4-Adresse oder einem IPv6-/64, 1024 von einem IPv4-/24 oder
  IPv6-/48. Ein Gerät, auf dem juist TLS beendet, nimmt 8192 an.
- `--max-conns N` und auf dem Ingress `--max-per-source N` ändern diese
  Grenzen: unter Linux in einem Drop-in für `juist-ingress` oder
  `juist-serve`, unter FreeBSD in `juist_ingress_args` oder `juist_serve_args`.
- Ein Client hat 10 Sekunden für sein TLS-Hello an den Ingress und eine
  Minute, um auf das seines Dienstes zu antworten. Eine Verbindung, die 5
  Minuten in beide Richtungen still ist, wird geschlossen.

## Fehlersuche

| Du siehst | Was zu tun ist |
|---|---|
| `the network has no domain to publish under` | Führ zuerst `juist network domain example.org` aus. |
| `this device is no ingress` | Ein Admin führt `juist grant DEVICE ingress` aus. |
| `warning: the network has no ingress, so nothing reaches it from the internet` | Gib einem Gerät mit öffentlicher Adresse die Rolle `ingress`. |
| auf vps, `juist status`: `Ingress` zeigt `not running on this device (juist ingress serve)` | Führ `juist ingress serve` auf vps aus. |
| `juist ingress` auf vps: `nothing to serve` | Noch ist kein Name veröffentlicht und bedient. Ist der Blick veraltet, sagt das ein Hinweis. |
| auf nas, `juist status`: `Published` zeigt `none (ready to serve)` | Auf nas ist noch kein Name veröffentlicht. Ein Admin führt `juist publish add nas immich` aus. |
| auf nas, `juist status`: `Published` zeigt `immich.example.org (not served)` | Führ `juist publish serve` auf nas aus. |
| `juist status`: `Published` zeigt `…, but ends TLS for none: the terminator does not run (juist publish serve)` | Führ `juist publish serve` aus. `journalctl -u juist-serve` zeigt, warum er stoppte. |
| `the ingress does not answer on 443: …` | `journalctl -u juist-ingress` zeigt warum, unter FreeBSD `/var/log/juist-ingress.log`. |
| `the terminator does not answer on …` oder `does not say it listens on …` | `journalctl -u juist-serve` zeigt warum, unter FreeBSD `/var/log/juist-serve.log`. |
| `another program holds port 443 on …, where juist would end TLS` | Beende das Programm, oder veröffentliche auf einem anderen Port. |
| `juist health`: `warning: another program holds port 80 on …` | Mitglieder, die `http://NAME` öffnen, landen bei diesem Programm statt bei der Umleitung. Lass es nur auf den Adressen lauschen, die es bedient. |
| `juist health`: `warning: no certificate for NAME: …` | Die CA hat keines ausgestellt, aus dem genannten Grund. Meist erreicht sie NAME nicht: Sein öffentliches DNS muss auf einen laufenden Ingress zeigen. |
| `warning: firewalld blocks tcp/443 on juist0, …` | `juist0` ist nicht in der firewalld-Zone `trusted`. Führ den `firewall-cmd`-Befehl aus dem Hinweis aus. |
| auf vps, `juist status`: `Ingress` zeigt `…; another program holds port 443/udp` | Ein anderes Programm, oft das HTTP/3 eines Webservers, belegt 443/udp. Browser bleiben bei TCP, bis es den Port freigibt. |
| `access: quic … refused: another name's flow from its address` | Ein Client hat einen UDP-Socket für Namen auf zwei Geräten genutzt. Der Ingress reicht so einen Socket nur an ein Gerät weiter. Browser nutzen einen Socket pro Name. |
| HTTP/3 unter Last langsamer als HTTP/2 | Die UDP-Puffer des Hosts sind klein: `sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000` auf dem Gerät, das TLS beendet. |

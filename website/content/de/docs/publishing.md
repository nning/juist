---
title: Dienste veröffentlichen
linkTitle: Dienste veröffentlichen
description: Einen Dienst auf einem deiner Geräte, etwa auf dem NAS zu Hause, unter einem Namen aus dem Internet erreichbar machen.
lead: Dienste auf deinen Mitgliedern, etwa auf dem NAS zu Hause, lassen sich unter einem Namen aus dem Internet erreichen. Ein Gerät mit öffentlicher Adresse leitet die Verbindungen weiter, und die Verschlüsselung endet erst beim Mitglied.
status: [Linux, FreeBSD]
---

## Worum es geht

Du betreibst zu Hause einen Dienst, etwa einen Dokumentenserver auf deinem
NAS, und willst ihn aus jedem Browser unter `docs.example.org` aufrufen. Dein
Router zu Hause muss dafür keinen Port öffnen, und seine Adresse taucht in
keinem öffentlichen DNS-Eintrag auf.

Zuerst ein paar Begriffe:

- Eine Domain ist ein Name im Internet, der dir gehört, etwa `example.org`.
- Ein DNS-Eintrag liegt bei deinem DNS-Anbieter und legt fest, auf welche
  Adresse ein Name verweist.
- TLS ist die Verschlüsselung, die ein Browser bei `https://`-Adressen
  verwendet.
- Ein Zertifikat beweist dem Browser, dass der Server wirklich
  `docs.example.org` ist. juist holt es bei Let's Encrypt.
- Eine Ingress ist ein Gerät in deinem Netz mit öffentlicher Adresse, etwa
  ein kleiner VPS, dem ein Admin die Rolle `ingress` gegeben hat. Sie nimmt
  Verbindungen auf Port 443 an, liest den Namen, den der Browser anfragt, und
  leitet die Verbindung durch den Tunnel an das Mitglied weiter, das diesen
  Namen veröffentlicht.

{{< flow publish >}}

Die Ingress entschlüsselt nichts und bekommt den Inhalt deshalb nie zu
sehen. TLS endet erst auf dem NAS, und das NAS reicht die entschlüsselte
Verbindung an den Dienst weiter. Eine einzige Ingress bedient alle Namen des
Netzes.

## Einrichten

{{< step on="dem Gerät eines Admins" >}}
Leg die Domain des Netzes fest und gib dem VPS die Rolle:

```sh
juist network domain example.org
juist grant vps ingress
```
{{< /step >}}

{{< step on="der Website deines DNS-Anbieters" >}}
Lass `*.example.org` auf die öffentliche Adresse des VPS verweisen, für alle
Namen auf einmal, oder nur `docs.example.org`.
{{< /step >}}

{{< step on="vps" as="der Ingress" >}}
```sh
juist ingress serve
```

Der Befehl fragt einmal nach sudo, startet den Dienst `juist-ingress` und
öffnet die Ports 443 (TCP und UDP, für HTTP/3) und 80 in firewalld oder ufw,
dazu die Ports, auf denen
Namen per TCP veröffentlicht sind, sobald sie kommen und gehen
([unten](#a-game-server-or-another-tcp-service)); unter FreeBSD bleibt pf
den eigenen Regeln des Hosts überlassen. Port 80 leitet nur auf https um.
{{< /step >}}

{{< step on="nas" as="dem Ziel" >}}
Der [Operator]({{< relref "docs/operator" >}}) des NAS, also der lokale
Benutzer, der das Gerät verwaltet, veröffentlicht den Namen und legt fest,
wohin die entschlüsselte Verbindung geht:

```sh
juist publish add docs 127.0.0.1:8080
```

`docs` geht an Port 443 des NAS. juist holt über die Ingress ein Zertifikat
und entschlüsselt TLS hier. Die Ausgabe lautet
`nas: publishes docs.example.org:443`, `serving docs.example.org` und
`ending TLS for docs.example.org to 127.0.0.1:8080`. Dann folgt der
CAA-Eintrag, der anderen Konten Zertifikate für den Namen verwehrt (siehe
unten), und beim ersten Mal
`warning: a server published from this device reaches the network and its LAN once compromised`.

Etwas zu veröffentlichen ist eine Änderung, die Admins vorbehalten ist. Hat
das NAS keinen Admin-Schlüssel, meldet es
`docs.example.org goes to 127.0.0.1:8080 once published on this device` und
nennt den Befehl, den ein Admin ausführen muss:
`juist publish add nas docs.example.org`.
Braucht eine Änderung mehr als einen Admin, wartet sie auf die anderen
([wie Änderungen bestätigt werden]({{< relref "docs/network-changes" >}})).
{{< /step >}}

`juist grant` und `juist publish add` nennen jeweils den nächsten Schritt und
das Gerät, auf dem er auszuführen ist. Ruft der Operator dieses Geräts die
Befehle dort auf, erledigen sie diesen Schritt gleich mit.
`juist invite vps --ingress` nimmt ein neues Gerät direkt als Ingress auf.

## Den Server vom Netz fernhalten {#keeping-the-server-away-from-your-network}

{{< note danger >}}
Bricht jemand in einen Server ein, den ein vollwertiges Mitglied
veröffentlicht, erreicht er von dort das Netz und das LAN dieses Mitglieds.
Veröffentliche von einem solchen Gerät nur, was du ohnehin ins Internet
stellen würdest.
{{< /note >}}

Ein **Service-Mitglied** hält den Server vom Netz fern. Es ist ein eigener
juistd ohne Privilegien, der neben dem Dienst läuft. Alle Geräte verbieten
ihm, von sich aus Verbindungen zu ihnen aufzubauen, nur seine Antworten
kommen durch.

{{< step on="dem Gerät eines Admins" >}}
```sh
juist invite immich --service immich
```

Damit wird das neue Gerät unter dem Namen `immich` als Service-Mitglied
aufgenommen, das `immich.example.org` veröffentlicht, und du bekommst den
Link zum Beitreten.
{{< /step >}}

{{< step on="dem Server" as="dem Service-Mitglied" >}}
Unter Docker kommt der Dienst in ein internes Netz, in dem außer ihm nur das
Service-Mitglied ist. Das Image des Service-Mitglieds (`make image` im
Quellbaum, dann `docker load`) hängt an diesem Netz und zusätzlich an einem
mit Zugang nach draußen:

```sh
docker network create --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated immich-only
docker network connect immich-only immich-server     # und aus allen anderen Netzen entfernen
docker run -d --name immich-juist -v immich-juist:/var/lib/juist -e JUIST_JOIN='juist:…' \
    juist:VERSION --serve immich=immich-server:2283
docker network connect immich-only immich-juist
```

Nach dem Start tritt es mit dem Link bei; ist es schon im Netz, ignoriert es
ihn. Wie der Beitritt lief, zeigt `docker logs immich-juist`, samt den
Wörtern zum Vergleichen, wenn die Einladung danach fragt.

Dasselbe als eine Compose-Datei, mit einem Webdienst zum Ausprobieren, für
Docker und Podman: [examples/service-member](https://github.com/nning/juist/tree/main/examples/service-member) im
Repository.

Ohne Docker startest du es mit `juistd --serve immich=127.0.0.1:2283` unter
einem beliebigen Benutzer. `--serve @=web:80` bedient die Domain selbst.
{{< /step >}}

Das Service-Mitglied entschlüsselt TLS selbst, mit einem Zertifikat von
Let's Encrypt, und beantwortet nur Anfragen an das, was es veröffentlicht,
sowie den Log-Abgleich. Der Dienst selbst hat keinen Zugang nach draußen. Muss
er beim ersten Start etwas herunterladen, erledigst du das also vorher. Der
isolierte Gateway-Modus von Docker 29 schottet den Dienst auch vom Host ab.
Ohne ihn erreicht der Dienst über das Gateway des Netzes alles, was auf dem
Host an allen Adressen lauscht.

## HTTP/3 {#http3}

Browser erreichen einen Namen über HTTP/3, also QUIC auf 443/udp, das eine
Runde weniger zum Verbinden braucht und bei einem verlorenen Paket auf einer
langsamen Leitung keine Zeit verliert, wenn sein Dienst HTTP spricht und
juist sein TLS beendet:

```sh
juist publish add docs 127.0.0.1:8080 --http3
```

Die Ausgabe lautet `ending TLS for docs.example.org to 127.0.0.1:8080, with
HTTP/3`, dazu ein DNS-Eintrag für deinen DNS-Anbieter,
`docs.example.org. HTTPS 1 . alpn="h3,h2"`, mit dem Browser HTTP/3 schon bei
der ersten Anfrage versuchen; ohne ihn tun sie es ab der zweiten, wie ihnen
der Header `Alt-Svc` sagt, den juist seinen Antworten anfügt. Ist 443/udp
irgendwo auf dem Weg gesperrt, bleiben Browser bei HTTP/2 über TCP.

- juist leitet das HTTP des Dienstes dann auch über TCP weiter und bietet
  Clients HTTP/2 an: Der Dienst bekommt jede Anfrage mit ihrem eigenen Host,
  wie bisher, und kein `X-Forwarded-For` oder anderen Header des Proxys. Mit
  `--http2` dazu fragt juist den Dienst per h2c.
- Die Statusseite bekommt HTTP/3 von selbst. Ein Service-Mitglied bietet es
  für seine Namen mit `juistd --serve NAME=ADRESSE --http3` an.
- WebSockets bleiben bei HTTP/1.1 über TCP; juist reicht sie weiter, wie
  sie sind.
- `--proxy` nennt dem Dienst den Client auf jeder seiner Verbindungen, wie
  über TCP.
- Ein Client, dessen Adresse wechselt, etwa ein Telefon vom WLAN ins LTE,
  verbindet sich neu; Freigaben bleiben bei TCP.
- Ein Client, der sich von einem UDP-Socket aus mit Namen auf zwei Geräten
  verbindet, wie der HTTP/3-Client von Go, erreicht per QUIC nur das erste
  Gerät.

## Ein Spieleserver oder ein anderer TCP-Dienst {#a-game-server-or-another-tcp-service}

Ein Dienst, der kein TLS spricht, etwa ein Minecraft-Server, bekommt auf
jeder Ingress einen eigenen Port. Jede Verbindung auf diesem Port reicht die
Ingress sofort an das Gerät weiter, ohne etwas davon zu lesen.

{{< step on="dem Gerät eines Admins" >}}
```sh
juist publish add nas mc 25565 --tcp
```

Das veröffentlicht Port 25565 von nas auf Port 25565 jeder Ingress, als
`mc.example.org`, und gibt `nas: publishes mc.example.org:25565/tcp` aus.
Mit `--tcp=PORT` nimmst du einen anderen öffentlichen Port:
`juist publish add nas ssh 22 --tcp=2222` gibt
`ssh.example.org:2222/tcp to 22` aus.
{{< /step >}}

{{< step on="nas" as="dem Ziel" >}}
Lauscht der Dienst auf allen Adressen, stimmt der Operator mit
`juist publish serve` zu. Lauscht er nur auf Loopback, reicht juist ihm die
Bytes unverändert weiter:

```sh
juist publish add mc 127.0.0.1:25565 --tcp
```

Die Ausgabe lautet `passing mc.example.org to 127.0.0.1:25565`.
{{< /step >}}

Spieler verbinden sich dann mit `mc.example.org:25565`. Jede Ingress hält
jeden solchen Port, solange ein Name darauf veröffentlicht ist, und
antwortet nicht, wo das Gerät ihn nicht bedient. Unter Linux lässt sie ihn
durch firewalld oder ufw, solange sie läuft, und schließt ihn wieder, sobald
der Name zurückgenommen ist oder die Ingress stoppt; `juist status` nennt
dort die Ports und die, die ein anderes Programm belegt.

- Einen TCP-Port veröffentlichen nur Admins, als Änderung des Netzes; die
  Rolle `publish` teilt nur auf 443.
- Ein öffentlicher Port gehört im Netz genau einem Namen. 80, 443 und juists
  eigene Ports, 41640 bis 41739, lehnt juist ab, ebenso einen, auf den ein
  eigener Name einer Ingress geht.
- Mitglieder erreichen den Namen direkt an seinem Gerät, wenn sein
  öffentlicher Port der Port des Geräts ist und er kein `--proxy` hat, sonst
  über die Ingress.
- Mit `--proxy` kommt die Adresse des Clients zuerst, in einem Header nach
  PROXY-Protokoll v2, den der Dienst erwarten muss: Paper und Velocity tun
  das, wenn man es ihnen sagt, Vanilla-Minecraft nicht.
- juist gibt keinen SRV-Eintrag aus. Ein Client, der einen nachschlägt, wie
  Minecraft bei einem Namen ohne Port, findet ihn, wenn du ihn bei deinem
  DNS-Anbieter anlegst:
  `_minecraft._tcp.mc.example.org. SRV 0 5 25565 mc.example.org.`
- UDP reicht juist nicht weiter, also auch nicht 19132/udp von Minecraft
  Bedrock.

{{< note caution >}}
Die Ingress sieht alles, was ein Protokoll überträgt, das sich nicht selbst
verschlüsselt, und ein CAA-Eintrag schützt da nichts. Veröffentliche so nur,
was sich selbst verschlüsselt, wie SSH, oder was jeder sehen darf.
{{< /note >}}

## Sofort teilen

Ein Gerät, dem ein Admin die Rolle `publish` gegeben hat
(`juist grant laptop publish`), kann unter seinem eigenen Namen
`laptop.example.org` veröffentlichen, ohne jedes Mal einen Admin zu fragen:

```sh
juist share ~/photos/2026          # unter https://laptop.example.org/ZUFALL/, bis Strg-C
juist publish 8000 --for 2h        # den Webserver dieses Geräts auf Port 8000, zwei Stunden lang
juist share -b --for 7d ~/talk.pdf # im Hintergrund, eine Woche lang
juist share                        # listet die Freigaben dieses Geräts samt Links
juist share --stop ~/talk.pdf      # beendet eine, nach Datei, Port oder Link, egal welcher Befehl sie hält
```

Eine Freigabe ist nur unter ihrem zufälligen Pfad abrufbar. Überall sonst
unter dem Namen kommt 404, außer `juist publish PORT` beantwortet es, und
Einträge wie `.git` bleiben verborgen. Ein
Verzeichnis erscheint als Liste, sortierbar nach Name, Größe oder Datum, und
lässt sich ganz oder ordnerweise als ZIP herunterladen; ein Ordner mit einer
`index.html` zeigt stattdessen diese Seite. Die
Freigabe endet mit dem Befehl oder nach Ablauf von `--for`, höchstens sieben
Tagen. Verschwindet das Gerät, endet sie spätestens zehn Minuten später.
Mit `--background` (`-b`) kehrt der Befehl zurück, sobald die Freigabe steht.
Sie läuft dann weiter, auch über einen Neustart von juistd hinweg unter
demselben Link, bis `juist share --stop` oder bis `--for` abläuft;
`juist share` listet sie samt Link, `juist status` zählt sie unter `Sharing`. Ein
einziges Zertifikat für den Namen des Geräts deckt alle Freigaben ab, ihre
Pfade landen also in keinem Zertifikats-Log. Ein Gerät hält bis zu 16
Freigaben gleichzeitig, jede unter ihrem eigenen Pfad, und daneben ein
`juist publish PORT`, das beantwortet, was kein Pfad einer Freigabe trifft.
`juist share --stop` ohne Namen beendet die einzige Freigabe; laufen mehrere,
sagt es, dass eine zu nennen ist. Wird es
[umbenannt]({{< relref "docs/network-changes" >}}), teilt es unter dem neuen
Namen, und `juist share` gibt den neuen Link aus.

## Eine Statusseite

Ein Gerät stellt die Statusseite des Netzes unter einem veröffentlichten Namen
bereit, im Aussehen dieser Website, hell oder dunkel, wie der Browser es
wünscht:

```sh
juist publish status-page status                # unter https://status.example.org/
juist publish status-page status --public all   # alle sehen alles
```

Mitglieder sehen alles: jedes Gerät mit Adressen und Rollen, wie das
bereitstellende Gerät es erreicht (direkt, über ein Relay, gesucht oder
abwesend) und wann es zuletzt von ihm gehört hat, die veröffentlichten Namen
und Freigaben und ob sie erreichbar sind, was Aufmerksamkeit braucht, und die
neuesten Änderungen im Log. Alle anderen sehen, was `--public` sagt:

| `--public` | Wer kein Mitglied ist, sieht |
|---|---|
| `none` | nichts: die Seite antwortet mit 404 |
| `services`, die Voreinstellung | die veröffentlichten Namen und Freigaben, und ob sie erreichbar sind |
| `network` | alles außer den Änderungen |
| `all` | alles |

Die Seite erkennt ein Mitglied an der Overlay-Adresse, von der seine
Verbindung kommt; wer über die Ingress kommt, ist Öffentlichkeit, was auch
immer die Ingress sagt. Solange sie offen ist, lädt sie sich alle 15 Sekunden
neu und taugt damit auch als Statusanzeige auf dem Handy. Einmal mit
`https://` geöffnet, bleibt der Browser für sie bei https.

Geräte, veröffentlichte Namen und Änderungen gehören dem Netz und sind auf
jedem Mitglied gleich. Erreichbarkeit und was Aufmerksamkeit braucht, sieht
das bereitstellende Gerät selbst, und die Seite sagt, welches: stell sie von
einem Gerät bereit, das immer läuft und die anderen gut erreicht. Eine Ingress
kann es nicht, sie hält Port 443 selbst.

{{< note caution >}}
Mit `--public network` oder `all` sieht jeder, der die Adresse kennt, die
Namen, Overlay-Adressen und Rollen deiner Geräte, mit `all` auch, wer welche
Änderung bestätigt hat. Sonst sehen das nur Mitglieder.
{{< /note >}}

`juist publish status-page status --public none` legt neu fest, was die
Öffentlichkeit sieht, und `juist publish remove status` nimmt die Seite
wieder weg. Es ist ein Name, für den juist TLS beendet, wie bei
`juist publish add NAME HOST:PORT`; ein Service-Mitglied stellt sie mit
`--serve status=status-page:all` bereit, und seine Erreichbarkeit ist dann
die eines Geräts, zu dem alle anderen keine Verbindung öffnen lassen.

## Gut zu wissen

- Ein veröffentlichter Name besteht aus genau einem Label unter der Domain,
  `docs.example.org`, oder ist die Domain selbst, `example.org`, ausgeschrieben:
  `juist publish add nas example.org`. Ein Gerät veröffentlicht höchstens 16
  Namen. Die Domain selbst veröffentlicht höchstens ein Gerät, und sie braucht bei deinem DNS-Anbieter eigene A- und
  AAAA-Einträge, die der Ingress, denn `*.example.org` deckt sie nicht ab. Ein
  CAA-Eintrag dort gilt für jeden Namen darunter, der keinen eigenen hat: Gib
  den Namen jedes Geräts ihre eigenen.
- Ein Name mit einem eigenen Eintrag, etwa dem CAA- oder HTTPS-Eintrag, den
  juist ausgibt, bekommt von `*.example.org` keine Adresse mehr: Gib ihm auch
  eigene A- und AAAA-Einträge, die der Ingress.
- Ein Dienst kann TLS auch selbst entschlüsseln und ein eigenes Zertifikat
  haben, so wie er es direkt im Internet täte. Ein Admin veröffentlicht ihn
  dann mit `juist publish add nas docs` auf Port 443, oder auf einem anderen
  Port, wenn du ihn hinter dem Namen angibst. Der Operator von nas stimmt mit
  `juist publish serve` zu.
- Mit `--proxy` gibt `juist publish add` dem Dienst die Adresse des Clients in
  einem Header nach PROXY-Protokoll v2 mit. Mitglieder erreichen den Namen
  dann ebenfalls über die Ingress.
- Eine Ingress reicht 16384 Verbindungen gleichzeitig weiter, 256 von einer
  Adresse und 1024 aus einem /24 oder /48; juist nimmt auf einem Gerät, wo
  es TLS beendet, 8192 an. `--max-conns N` und, für die Ingress,
  `--max-per-source N` ändern das: unter Linux in einem Drop-in für
  `juist-ingress` oder `juist-serve`, unter FreeBSD in `juist_ingress_args`
  oder `juist_serve_args`.
- Mit `--http2` bietet `juist publish add NAME HOST:PORT` Clients HTTP/2 an,
  für einen Dienst, der es neben HTTP/1.1 auch ohne TLS (h2c) annimmt. Ein
  Browser öffnet dann eine Verbindung statt bis zu sechs. Ein Dienst, der
  nur HTTP/1.1 kann, scheitert damit.
- Jedes Mitglied unter Linux mit systemd-resolved schickt die ganze Domain an
  juistd. Es beantwortet einen auf 443 veröffentlichten oder geteilten Namen
  mit der Adresse seines Geräts, solange es erreichbar ist,
  sodass Mitglieder ihn direkt durch den Tunnel erreichen, mit demselben
  Zertifikat, und reicht jeden anderen Namen der Domain weiter wie bisher,
  für höchstens 30 Sekunden gemerkt, sodass ein neu veröffentlichter Name
  bald direkt erreicht wird. DNSSEC ist für die Domain auf Mitgliedern aus ([Namen]({{< relref "docs/names" >}})).
  `http://` zu einem solchen Namen geht an Port 80 des Geräts, wo juist auf
  https umleitet, es sei denn, ein anderes Programm lauscht dort auf allen
  Adressen: Dann antwortet dieses, und `juist status` warnt davor.
- `juist publish` listet die veröffentlichten Namen auf und zeigt, wohin
  dieses Gerät seine eigenen weiterleitet. `juist publish remove docs` nimmt
  einen Namen auf diesem Gerät zurück, `juist publish remove nas docs` einen
  auf einem anderen. `juist publish serve --stop` beendet das Bedienen, merkt
  sich aber, wohin die Namen gehen. `juist ingress serve --stop` beendet die
  Ingress.
- Eine Ingress und juists eigenes TLS laufen unter Linux und FreeBSD, jeweils
  für das Standardnetz des Geräts. Betreibt ein FreeBSD-Host pf, lässt pf 443
  per TCP und UDP, 80 und die Ports, auf denen Namen per TCP veröffentlicht
  sind, nach den eigenen Regeln des Hosts durch.
- `juist network domain off` lehnt juist ab, solange ein Gerät Namen unter der
  Domain veröffentlicht, und nennt das `juist publish remove`, das zuerst
  kommt.
- Eine Ingress ist nie Voucher oder Exit-Node, veröffentlicht nichts unter
  ihrem eigenen Namen oder auf 80, 443 oder einem Port, auf dem ein Name per
  TCP veröffentlicht ist, die sie selbst belegt, und routet
  kein Subnetz; ein Service-Mitglied hat keine weitere Rolle. `juist grant`
  nennt die Rolle, die im Weg ist. Jedes
  Mitglied nimmt von ihr nur Verbindungen zu den Ports an, die es
  veröffentlicht und bedient, sowie den Log-Abgleich, dazu Antworten auf
  das, was es selbst geöffnet hat, Pings eingeschlossen, und ICMP-Fehler zu
  seinen eigenen Verbindungen.
  Alles andere von ihr wird verworfen.
- Ein Client, der nicht binnen einer Minute auf das TLS-Hello seines
  Dienstes antwortet, wird getrennt, und jede Verbindung, die in beide
  Richtungen still ist, nach 5 Minuten.
- Ein Client hat 10 Sekunden, um der Ingress sein TLS-Hello zu schicken.
- Die Ingress schreibt für jede Verbindung eine Zeile ins Log: Adresse und
  Port des Clients, den angefragten Namen, was daraus wurde (`spliced`,
  `not served`, `no hello`, `target unreachable`, `refused`), die Bytes in
  beide Richtungen und die Dauer; auf Port 80 auch Methode, Pfad, Status und
  User-Agent, und auf einem per TCP veröffentlichten Port den Port und den
  Namen, an den er geht; einen QUIC-Fluss, sobald er endet, als
  `access: quic`, `not proven`, wenn sein Client nie einen Handshake
  abschloss, wie es eine gefälschte Adresse nicht kann. Zeilen solcher Flüsse
  und abgewiesener QUIC-Verbindungen kommen höchstens einmal pro Sekunde und
  sagen, wie viele weitere ungesagt blieben. Jenseits von Port 80 sieht sie weder Pfad noch User-Agent, weil
  TLS erst am Gerät endet. `journalctl -u juist-ingress` zeigt sie, unter
  FreeBSD `/var/log/juist-ingress.log`, so lange, wie das Journal oder newsyslog sie behält.
- Die Ingress läuft unter einem eigenen Benutzer `juist-ingress`, hat keinen
  Schlüssel des Netzes und darf juistd nur eines fragen: was veröffentlicht
  ist.
- Ist der Stand des Netzes auf der Ingress veraltet, bedient sie nichts.
  Antwortet ihr juistd nicht mehr, sind die Namen innerhalb von fünfzehn
  Sekunden weg.
- `juist revoke vps ingress`, oder `service`, macht das Gerät wieder zu einem
  gewöhnlichen Mitglied, wovor juist warnt:
  `warning: vps is confined no more, now a member like any other`. Ein
  möglicherweise kompromittiertes entfernst du mit `juist remove`. Ohne die
  Ingress-Rolle führst du darauf `juist ingress serve --stop` aus.

{{< note caution >}}
Wer die Ingress kontrolliert, kann sich ein Zertifikat für deine Namen
ausstellen lassen und öffentliche Clients abfangen, ebenso Mitglieder, die
einen Namen über sie erreichen: auf einem anderen Port als 443, hinter
`--proxy` oder ohne systemd-resolved. Mitglieder, die einen Namen auf 443 zu seinem Gerät
auflösen, verbinden sich direkt mit ihm. Verhindern lässt sich das mit einem CAA-Eintrag, also
einem DNS-Eintrag, der festlegt, wer Zertifikate für einen Namen ausstellen
darf, sofern er an das ACME-Konto des Ziels gebunden ist.
`juist publish add NAME HOST:PORT` gibt diesen Eintrag aus, bei einem
Service-Mitglied steht er im Log des Terminators.
{{< /note >}}

## Wenn etwas nicht klappt

| Was du siehst | Was du tun kannst |
|---|---|
| `the network has no domain to publish under` | Führe zuerst `juist network domain example.org` aus. |
| auf nas, `juist status`: `Published` zeigt `not served here: not agreed to on this device (juist publish serve)` | Führe auf nas `juist publish serve` aus. |
| auf vps, `juist status`: `Ingress` zeigt `not running on this device (juist ingress serve)` | Führe auf vps `juist ingress serve` aus. |
| `juist ingress` auf vps: `nothing to serve` | Es ist noch kein Name veröffentlicht und bedient. Ist der Stand veraltet, weist ein Hinweis darauf hin. |
| `the ingress does not answer on 443: …` | Den Grund zeigt `journalctl -u juist-ingress`, unter FreeBSD `/var/log/juist-ingress.log`. |
| `the terminator does not answer on …` | Den Grund zeigt `journalctl -u juist-serve`, unter FreeBSD `/var/log/juist-serve.log`. |
| `this device holds no publish role` | Ein Admin führt `juist grant GERÄT publish` aus. |
| `juist status`: `Sharing` zeigt `reached by nobody: the terminator does not run` | `juist share` startet ihn. Warum er stand, zeigt `journalctl -u juist-serve`. |
| `juist status`: `Published` zeigt `…, but ends TLS for none: the terminator does not run (juist publish serve)` | Führe `juist publish serve` aus. Warum er stand, zeigt `journalctl -u juist-serve`. |
| `the terminator does not say it listens on …` | Er ist nicht rechtzeitig gestartet. Den Grund zeigt `journalctl -u juist-serve`. |
| `juist status`: `warning: another program holds port 80 on …` | Mitglieder, die `http://NAME` öffnen, landen bei diesem Programm statt bei der Umleitung auf https. Lass es nur auf den Adressen lauschen, die es bedient, und öffne den Namen bis dahin mit `https://`. |
| `juist status`: `warning: no certificate for NAME: …` | Die CA hat keines ausgestellt, aus dem genannten Grund. Meist erreicht sie NAME nicht: Das öffentliche DNS von NAME muss auf ein laufendes Ingress zeigen. Bis dahin scheitert TLS bei jedem Client. |
| `another program holds port 443 on …, where juist would end TLS` | Beende dieses Programm oder veröffentliche auf einem anderen Port. |
| auf vps, `juist status`: `Ingress` zeigt `…; another program holds port 443/udp` | Ein anderes Programm, oft das HTTP/3 eines Webservers, belegt 443/udp auf der Ingress; Browser bleiben bei TCP, bis es den Port freigibt, und dann übernimmt ihn die Ingress. |
| `access: quic … refused: another name's flow from its address` | Ein Client hat sich von einem UDP-Socket aus mit Namen auf zwei Geräten verbunden; die Ingress reicht ihn nur an eines davon weiter. Browser nehmen für jede Verbindung einen eigenen Socket. |
| HTTP/3 unter Last langsamer als HTTP/2 | Die UDP-Puffer des Hosts sind klein: `sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000` auf dem Gerät, das TLS beendet. |
| `another program holds port 25565 on …, where juist would pass NAME by TCP` | Der Dienst lauscht auf allen Adressen, auch auf den Overlay-Adressen des Geräts: Veröffentliche stattdessen seinen Port, wie der Hinweis sagt, und stimme mit `juist publish serve` zu. |
| auf vps, `juist status`: `Ingress` zeigt `…; another program holds port 22` | Ein Programm auf der Ingress, oft ihr sshd, belegt einen Port, auf dem ein Name per TCP veröffentlicht ist; juist überlässt ihn dann diesem Programm und den Regeln der Firewall. Veröffentliche den Namen mit `--tcp=PORT` auf einem anderen Port. |
| `this device publishes a port already` | Ein anderes `juist publish PORT` läuft, vielleicht im Hintergrund: `juist share` listet es, `juist share --stop PORT` beendet es. |
| `this device holds 16 shares already` | `juist share` listet sie; beende eine mit `juist share --stop`. |
| `this device is no ingress` | Ein Admin führt `juist grant GERÄT ingress` aus. |
| `warning: the network has no ingress, so nothing reaches it from the internet` | Gib einem Gerät mit öffentlicher Adresse die Rolle `ingress`. |
| `warning: nothing answers on 127.0.0.1:8000 yet` | Starte den Webserver, auf den `juist publish 8000` zeigt. |
| `warning: firewalld blocks tcp/443 on juist0, …` | `juist0` liegt nicht in der firewalld-Zone `trusted`, die das Paket nur bei der ersten Installation setzt. Führe den `firewall-cmd`-Befehl aus dem Hinweis aus. |

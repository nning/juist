---
title: Dienste veröffentlichen
linkTitle: Dienste veröffentlichen
description: Einen Dienst auf einem deiner Geräte, etwa auf dem NAS zu Hause, unter einem Namen aus dem Internet erreichbar machen.
lead: Dienste auf deinen Mitgliedern, etwa auf dem NAS zu Hause, lassen sich unter einem Namen aus dem Internet erreichen. Ein Gerät mit öffentlicher Adresse leitet die Verbindungen weiter, und die Verschlüsselung endet erst beim Mitglied.
status: [Linux, FreeBSD]
---

## So funktioniert es

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
- Ein Ingress ist ein Gerät in deinem Netz mit öffentlicher Adresse, etwa
  ein kleiner VPS, dem ein Admin die Rolle `ingress` gegeben hat. Er nimmt
  Verbindungen auf Port 443 an, liest den Namen, den der Browser anfragt, und
  leitet die Verbindung durch den Tunnel an das Mitglied weiter, das diesen
  Namen veröffentlicht.

{{< flow publish >}}

Der Ingress entschlüsselt nichts und bekommt den Inhalt deshalb nie zu
sehen. TLS endet erst auf dem NAS, und das NAS reicht die entschlüsselte
Verbindung an den Dienst weiter. Ein einziger Ingress bedient alle Namen des
Netzes.

Jede Art zu veröffentlichen braucht die Domain und den Ingress. Beides
richten die ersten drei Schritte unten einmal ein. Danach kommt es darauf an,
was du veröffentlichen willst:

| Was | Wo |
|---|---|
| einen Webdienst auf einem Mitglied, unter einem eigenen Namen | [Einrichten](#einrichten), Schritt 4 |
| einen Server, dem du keinen Zugang zu deinem Netz geben willst | [Den Server vom Netz fernhalten](#keeping-the-server-away-from-your-network) |
| einen Namen, den nur Mitglieder öffnen können | [Namen nur für Mitglieder](#names-for-members-alone) |
| einen Spieleserver oder einen anderen Dienst ohne TLS | [Spieleserver und andere TCP-Dienste](#a-game-server-or-another-tcp-service) |
| eine Datei, ein Verzeichnis oder einen lokalen Webserver, sofort | [Sofort teilen](#sofort-teilen) |
| eine Übersicht über die Geräte des Netzes | [Statusseite](#statusseite) |

## Einrichten

{{< step on="dem Gerät eines Admins" >}}
Leg die Domain des Netzes fest und gib dem VPS die Rolle:

```sh
juist network domain example.org
juist grant vps ingress
```
{{< /step >}}

{{< step on="der Website deines DNS-Anbieters" >}}
Lass `*.example.org` auf die öffentliche Adresse des VPS verweisen, dann gilt
das für alle Namen, oder nur `docs.example.org`.
{{< /step >}}

{{< step on="vps" as="der Ingress" >}}
```sh
juist ingress serve
```

Der Befehl fragt einmal nach sudo und startet den Dienst `juist-ingress`. Er
öffnet die Ports 443 (TCP und UDP, für HTTP/3) und 80 in firewalld oder ufw,
dazu die Ports von Namen, die per TCP veröffentlicht sind, und schließt sie
wieder, wenn diese Namen verschwinden
([unten](#a-game-server-or-another-tcp-service)). Unter FreeBSD bleibt pf den
eigenen Regeln des Hosts überlassen. Port 80 leitet nur auf https um.
{{< /step >}}

{{< step on="nas" as="dem Ziel" >}}
Der [Operator]({{< relref "docs/operator" >}}) des NAS, also der lokale
Benutzer, der das Gerät verwaltet, veröffentlicht den Namen und legt fest,
wohin die entschlüsselte Verbindung geht:

```sh
juist publish add docs 127.0.0.1:8080
```

`docs` geht an Port 443 des NAS. juist holt über den Ingress ein Zertifikat
und entschlüsselt TLS hier. Die Ausgabe lautet
`nas: publishes docs.example.org:443`, `serving docs.example.org` und
`ending TLS for docs.example.org to 127.0.0.1:8080`. Dann folgt der
CAA-Eintrag, der anderen ACME-Konten Zertifikate für den Namen verwehrt
(siehe unten), und beim ersten Mal
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

Ein **Service-Mitglied** hält den Server von deinem Netz fern. Es ist ein
eigener juistd ohne Privilegien, der neben dem Dienst läuft. Kein Gerät nimmt
Verbindungen an, die es aufbaut; nur seine Antworten kommen durch.

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
Service-Mitglied ist. Den Container des Service-Mitglieds hängst du an dieses
Netz und zusätzlich an eines mit Zugang ins Internet. Sein Image baust du mit
`make image` im Quellbaum und lädst es mit `docker load`:

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

Ohne Docker ist ein Service-Mitglied ein juistd unter einem beliebigen
Benutzer. Es braucht kein root und legt kein eigenes Gerät an:

```sh
juistd --home ~/immich-juist --serve immich=127.0.0.1:2283 --join 'juist:…'
```

In `--home` liegen seine Schlüssel und das Log; beim ersten Start tritt es mit
dem Link bei, danach ignoriert es ihn. Was es ausgibt, ist sein Log: Starte es
deshalb über deinen Dienstverwalter, etwa eine systemd-Benutzer-Unit, die es
am Laufen hält und sein Log aufbewahrt. `--serve @=web:80` bedient die Domain
selbst.
{{< /step >}}

Das Service-Mitglied entschlüsselt TLS selbst, mit einem Zertifikat von
Let's Encrypt, und beantwortet nur Anfragen an die Namen, die es
veröffentlicht, sowie den Log-Abgleich. Der Dienst selbst hat keinen Zugang
ins Internet. Muss er beim ersten Start etwas herunterladen, erledigst du das
also vorher. Der isolierte Gateway-Modus von Docker 29 schottet den Dienst
auch vom Host ab. Ohne ihn erreicht der Dienst über das Gateway des Netzes
alles, was auf dem Host an allen Adressen lauscht.

## HTTP/3 {#http3}

Spricht der Dienst eines Namens HTTP und beendet juist sein TLS, können
Browser ihn über HTTP/3 erreichen, also über QUIC auf 443/udp. Der
Verbindungsaufbau braucht eine Runde weniger, und auf einer langsamen Leitung
kostet ein verlorenes Paket keine Zeit:

```sh
juist publish add docs 127.0.0.1:8080 --http3
```

Die Ausgabe lautet `ending TLS for docs.example.org to 127.0.0.1:8080, with HTTP/3`,
dazu kommt ein DNS-Eintrag für deinen DNS-Anbieter,
`docs.example.org. HTTPS 1 . alpn="h3,h2"`. Mit diesem Eintrag versuchen
Browser HTTP/3 schon bei der ersten Anfrage. Ohne ihn tun sie es ab der
zweiten, sobald ihnen der Header `Alt-Svc`, den juist seinen Antworten
anfügt, davon erzählt hat. Ist 443/udp irgendwo auf dem Weg gesperrt, bleiben
Browser bei HTTP/2 über TCP.

- Mit `--http3` leitet juist das HTTP des Dienstes auch über TCP weiter und
  bietet Clients HTTP/2 an. Der Dienst bekommt jede Anfrage weiterhin mit
  ihrem eigenen Host und weder `X-Forwarded-For` noch einen anderen Header
  des Proxys. Mit `--http2` dazu spricht juist den Dienst per h2c an.
- Die Statusseite bietet HTTP/3 immer an. Ein Service-Mitglied bietet es für
  seine Namen mit `juistd --serve NAME=ADRESSE --http3` an.
- WebSockets bleiben bei HTTP/1.1 über TCP; juist reicht sie unverändert
  weiter.
- `--proxy` teilt dem Dienst auf jeder seiner Verbindungen die Adresse des
  Clients mit, wie über TCP.
- Ein Client, dessen Adresse wechselt, etwa ein Telefon vom WLAN ins LTE,
  muss sich neu verbinden.
- Freigaben laufen nur über TCP.
- Ein Client, der sich von einem UDP-Socket aus mit Namen auf zwei
  verschiedenen Geräten verbindet, wie der HTTP/3-Client von Go, erreicht per
  QUIC nur das erste Gerät.

## Namen nur für Mitglieder {#names-for-members-alone}

Ein Name kann wie jeder andere ein Zertifikat der CA haben und trotzdem nur
für Mitglieder des Netzes erreichbar sein, etwa die Fotos der Familie unter
`photos.example.org`:

{{< step on="dem Gerät eines Admins" >}}
```sh
juist publish add nas photos --members
```

Die Ausgabe lautet `nas: publishes photos.example.org:443 (members)`, und
`juist publish` führt den Namen mit `(members)`.
{{< /step >}}

{{< step on="nas" as="dem Ziel" >}}
```sh
juist publish add photos 127.0.0.1:2342
```

juist holt das Zertifikat über den Ingress und beendet TLS hier, wie bei
jedem Namen.

Gibst du auch hier `--members` an, wird der Dienst selbst als nur für
Mitglieder markiert: juist schickt den Namen nie an ihn, solange das Log den
Namen als öffentlich führt. Davor warnen `juist health` und
`juist publish add`, und `juist publish` zeigt den Dienst mit `(members)`.
Spätere Befehle behalten die Markierung bis
`--members=false`. Ein Service-Mitglied markiert seine Dienste ebenso mit
`juistd --serve NAME=ADRESSE --members`.
{{< /step >}}

Ohne [Zugriffsregeln]({{< relref "docs/access" >}}) darf jedes Mitglied den
Namen öffnen. Gibt es Regeln, dürfen es nur die Mitglieder, für die eine
Regel den Namen nennt, etwa `pass from <family> to name photos`; eine Regel
zum Gerät oder zu `any` öffnet den Namen nicht.

- Der Ingress reicht den Namen an niemanden weiter außer an die CA, die ihn
  beim Ausstellen und Erneuern des Zertifikats per TLS auf 443 prüft. Alle
  anderen bekommen nichts, und der Ingress protokolliert `members only`. Der
  öffentliche DNS-Eintrag des Namens zeigt trotzdem auf den Ingress, damit die
  CA ihn erreicht.
- Das Gerät, das TLS beendet, nimmt den Namen nur von den Mitgliedern an, für
  die er gedacht ist. Es erkennt sie an der Adresse im Netz, von der ihre
  Verbindung kommt. Vom Ingress nimmt es nur die Prüfung der CA an, ein
  übernommener Ingress kommt also nicht weiter.
- Unter Linux und FreeBSD erreichen Mitglieder den Namen direkt an seinem
  Gerät, wie jeden Namen auf 443. Geräte, die die Namen des Netzes über
  öffentliches DNS auflösen, erreichen ihn gar nicht: solche, auf denen
  `juist health` sagt, dass die Namen nicht aufgelöst werden, und vor jedem
  solchen Namen warnt, und die Android-App.
- Der Name braucht einen eigenen Dienst. juist bedient einen Namen nur für
  Mitglieder nicht, wenn ein anderer Name oder eine Freigabe auf demselben
  Gerät denselben Dienst erreicht und juist deren Bytes unverändert
  weiterreicht. Ein Client des anderen Namens könnte den Dienst sonst per
  Host-Header nach dem Namen nur für Mitglieder fragen. `juist health` meldet
  das. Namen, deren HTTP juist weiterleitet (`--http3`), bleiben an ihren
  eigenen Host gebunden und zählen nicht. Lass den Dienst nur auf 127.0.0.1
  lauschen, und leite keine Namen anderer Geräte an ihn weiter.
- Das Gerät selbst erreicht den Namen nicht über juist. Sonst käme jedes
  Programm darauf an ihn heran, auch eines, das ein Client eines öffentlichen
  Dienstes auf demselben Gerät Anfragen schicken lassen kann. Auf diesem Gerät
  erreichst du den Dienst unter seiner eigenen Adresse.
- Ein Name nur für Mitglieder liegt immer auf 443, per TLS, ohne `--proxy`.
  Ein erneutes `juist publish add nas photos` ohne `--members` lässt ihn so;
  erst `--members=false` macht ihn öffentlich.
- Wie bei jedem Zertifikat steht der Name in den öffentlichen
  Zertifikatslogs der CA. Wie er heißt, ist kein Geheimnis, nur was er
  bereitstellt.

## Spieleserver und andere TCP-Dienste {#a-game-server-or-another-tcp-service}

Ein Dienst, der kein TLS spricht, etwa ein Minecraft-Server, bekommt auf
jedem Ingress einen eigenen Port. Jede Verbindung auf diesem Port reicht der
Ingress sofort an das Gerät weiter, ohne etwas davon zu lesen.

{{< step on="dem Gerät eines Admins" >}}
```sh
juist publish add nas mc 25565 --tcp
```

Das veröffentlicht Port 25565 von nas auf Port 25565 jedes Ingress, als
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

Spieler verbinden sich dann mit `mc.example.org:25565`. Jeder Ingress lauscht
auf einem solchen Port, solange ein Name darauf veröffentlicht ist, und
antwortet nicht, solange das Gerät ihn nicht bedient. Unter Linux öffnet der
Ingress den Port in firewalld oder ufw, solange er läuft, und schließt ihn
wieder, sobald der Name zurückgenommen ist oder der Ingress stoppt.
`juist status` auf dem Ingress nennt diese Ports und die, die ein anderes
Programm belegt.

- Einen TCP-Port veröffentlichen nur Admins, als Änderung des Netzes. Die
  Rolle `publish` teilt nur auf 443.
- Jeder öffentliche Port gehört im Netz genau einem Namen. Die Ports 80, 443
  und juists eigene Ports, 41640 bis 41739, lehnt juist ab, ebenso einen
  Port, auf dem ein Ingress einen eigenen Namen bedient.
- Mitglieder erreichen den Namen direkt an seinem Gerät, wenn sein
  öffentlicher Port der Port des Geräts ist und er kein `--proxy` hat. Sonst
  gehen sie über den Ingress.
- Mit `--proxy` kommt zuerst die Adresse des Clients, in einem Header nach
  PROXY-Protokoll v2, den der Dienst erwarten muss. Paper und Velocity tun
  das, wenn man es einstellt, Vanilla-Minecraft nicht.
- juist gibt keinen SRV-Eintrag aus. Clients, die einen nachschlagen, wie
  Minecraft bei einem Namen ohne Port, finden ihn, wenn du ihn bei deinem
  DNS-Anbieter anlegst:
  `_minecraft._tcp.mc.example.org. SRV 0 5 25565 mc.example.org.`
- UDP reicht juist nicht weiter, also auch nicht 19132/udp von Minecraft
  Bedrock.

{{< note caution >}}
Der Ingress sieht alles, was ein Protokoll überträgt, das sich nicht selbst
verschlüsselt, und ein CAA-Eintrag hilft da nicht. Veröffentliche so nur,
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

Eine Freigabe ist nur unter ihrem zufälligen Pfad abrufbar. Jeder andere Pfad
unter dem Namen antwortet mit 404, außer ein `juist publish PORT` bedient ihn.
Einträge wie `.git` bleiben verborgen. Ein Verzeichnis erscheint als Liste,
sortierbar nach Name, Größe oder Datum, und lässt sich ganz oder ordnerweise
als ZIP herunterladen. Ein Ordner mit einer `index.html` zeigt stattdessen
diese Seite.

Eine Freigabe endet mit ihrem Befehl oder nach Ablauf von `--for`, spätestens
nach sieben Tagen. Verschwindet das Gerät, endet sie spätestens zehn Minuten
später. Mit `--background` (`-b`) kehrt der Befehl zurück, sobald die Freigabe
steht. Sie läuft dann weiter, bis `juist share --stop` oder `--for` sie
beendet, auch über einen Neustart von juistd hinweg unter demselben Link.
`juist share` listet sie samt Link, und `juist status` zählt sie unter
`Sharing`.

Ein einziges Zertifikat für den Namen des Geräts deckt alle Freigaben ab,
ihre Pfade landen also in keinem Zertifikatslog. Ein Gerät hält bis zu 16
Freigaben gleichzeitig, jede unter ihrem eigenen Pfad, und daneben ein
`juist publish PORT`, das jeden Pfad beantwortet, den keine Freigabe hat.
`juist share --stop` ohne Argument beendet die einzige Freigabe; laufen
mehrere, sagt es, dass eine zu nennen ist. Wird das Gerät
[umbenannt]({{< relref "docs/network-changes" >}}), teilt es unter dem neuen
Namen, und `juist share` gibt den neuen Link aus.

## Statusseite

Ein Gerät kann die Statusseite des Netzes unter einem veröffentlichten Namen
bereitstellen, im Aussehen dieser Website, hell oder dunkel, wie der Browser
es wünscht:

```sh
juist publish status-page status                # unter https://status.example.org/
juist publish status-page status --public all   # alle sehen alles
```

Mitglieder sehen alles:

- jedes Gerät mit Adressen und Rollen, und dem neuesten Schema, das sein juist
  kennt, markiert, wo es älter ist als das des bereitstellenden Geräts;
- wie das bereitstellende Gerät es erreicht (direkt, über ein Relay, gesucht,
  abwesend oder veraltet, wenn darauf ein älteres juist läuft) und wann es
  zuletzt von ihm gehört hat;
- die veröffentlichten Namen und Freigaben, ob sie erreichbar sind, und
  `members only` an denen, die nur für Mitglieder sind;
- was Aufmerksamkeit braucht;
- das Schema des Netzes, und das dieses juist, wo es neuer ist, wie
  `juist status` sie zeigt;
- die neuesten Änderungen im Log.

Alle anderen sehen, was `--public` zulässt, aber nie einen Namen nur für
Mitglieder:

| `--public` | Was Nicht-Mitglieder sehen |
|---|---|
| `none` | nichts: die Seite antwortet mit 404 |
| `services`, die Voreinstellung | die veröffentlichten Namen und Freigaben, und ob sie erreichbar sind |
| `network` | alles außer den Änderungen |
| `all` | alles |

Die Seite erkennt ein Mitglied an der Overlay-Adresse, von der seine
Verbindung kommt. Wer über den Ingress kommt, zählt als Öffentlichkeit, was
auch immer der Ingress behauptet. Solange die Seite offen ist, lädt sie sich
alle 15 Sekunden neu und taugt damit auch als Statusanzeige auf dem Handy.
Einmal mit `https://` geöffnet, bleibt der Browser für sie bei https.

Geräte, veröffentlichte Namen und Änderungen gehören dem Netz und sind auf
jedem Mitglied gleich. Erreichbarkeit und was Aufmerksamkeit braucht, zeigt
die Seite aus Sicht des bereitstellenden Geräts und nennt es. Stell sie also
von einem Gerät bereit, das immer läuft und die anderen gut erreicht. Ein
Ingress kann das nicht, weil er Port 443 selbst belegt.

{{< note caution >}}
Mit `--public network` oder `all` sieht jeder, der die Adresse kennt, die
Namen, Overlay-Adressen und Rollen deiner Geräte, mit `all` auch, wer welche
Änderung bestätigt hat. Sonst sehen das nur Mitglieder.
{{< /note >}}

Ein erneutes `juist publish status-page status --public none` ändert, was die
Öffentlichkeit sieht, und `juist publish remove status` nimmt die Seite
wieder weg. Sie ist ein Name, für den juist TLS beendet, wie bei
`juist publish add NAME HOST:PORT`. Ein Service-Mitglied stellt sie mit
`--serve status=status-page:all` bereit. Die Erreichbarkeit, die sie zeigt,
ist dann die eines Geräts, von dem die anderen keine Verbindungen annehmen.

## Namen und DNS-Einträge

- Ein veröffentlichter Name besteht aus genau einem Label unter der Domain,
  etwa `docs.example.org`, oder ist die Domain selbst, `example.org`,
  ausgeschrieben: `juist publish add nas example.org`. Ein Gerät
  veröffentlicht höchstens 16 Namen.
- Die Domain selbst kann nur ein Gerät veröffentlichen. Sie braucht bei
  deinem DNS-Anbieter eigene A- und AAAA-Einträge, die auf den Ingress
  zeigen, denn `*.example.org` deckt sie nicht ab. Ein CAA-Eintrag an der
  Domain gilt für jeden Namen darunter, der keinen eigenen hat. Gib deshalb
  den Namen jedes Geräts ihre eigenen.
- Ein Name mit einem eigenen Eintrag, etwa dem CAA- oder HTTPS-Eintrag, den
  juist ausgibt, bekommt von `*.example.org` keine Adresse mehr. Gib ihm auch
  eigene A- und AAAA-Einträge, die auf den Ingress zeigen.
- Jedes Mitglied unter Linux und FreeBSD schickt Anfragen zur ganzen
  Domain an juistd. juistd beantwortet einen auf 443 veröffentlichten oder
  geteilten Namen mit der Adresse seines Geräts, solange es erreichbar ist.
  So erreichen Mitglieder ihn direkt durch den Tunnel, mit demselben
  Zertifikat. Alle anderen Namen der Domain reicht juistd weiter wie bisher,
  und ihre Antworten werden höchstens 30 Sekunden zwischengespeichert, damit
  ein neu veröffentlichter Name bald direkt erreicht wird. DNSSEC ist für die
  Domain auf Mitgliedern aus ([Namen]({{< relref "docs/names" >}})).
- `http://` zu einem solchen Namen geht an Port 80 des Geräts, wo juist auf
  https umleitet. Lauscht dort ein anderes Programm auf allen Adressen,
  antwortet stattdessen dieses, und `juist health` warnt davor.

## Weitere Optionen

- Ein Dienst kann TLS auch selbst entschlüsseln und ein eigenes Zertifikat
  haben, so wie er es direkt im Internet täte. Ein Admin veröffentlicht ihn
  dann mit `juist publish add nas docs` auf Port 443, oder auf einem anderen
  Port, wenn du ihn hinter dem Namen angibst. Der Operator von nas stimmt mit
  `juist publish serve` zu.
- Mit `--proxy` gibt `juist publish add` dem Dienst die Adresse des Clients in
  einem Header nach PROXY-Protokoll v2 mit. Mitglieder erreichen den Namen
  dann ebenfalls über den Ingress.
- Mit `--http2` bietet `juist publish add NAME HOST:PORT` Clients HTTP/2 an,
  für einen Dienst, der neben HTTP/1.1 auch HTTP/2 ohne TLS (h2c) annimmt.
  Ein Browser öffnet dann eine Verbindung statt bis zu sechs. Ein Dienst, der
  nur HTTP/1.1 kann, scheitert damit.

## Grenzen

- Ein Ingress reicht bis zu 16384 Verbindungen gleichzeitig weiter, 256 von
  einer IPv4-Adresse oder einem IPv6-/64 und 1024 aus einem IPv4-/24 oder
  IPv6-/48. Ein Gerät, auf dem juist TLS
  beendet, nimmt 8192 an. `--max-conns N` und, für den Ingress,
  `--max-per-source N` ändern diese Grenzen: unter Linux in einem Drop-in für
  `juist-ingress` oder `juist-serve`, unter FreeBSD in `juist_ingress_args`
  oder `juist_serve_args`.
- Ein Client hat 10 Sekunden, um dem Ingress sein TLS-Hello zu schicken.
- Ein Client, der nicht binnen einer Minute auf das TLS-Hello seines
  Dienstes antwortet, wird getrennt, ebenso jede Verbindung, die 5 Minuten
  lang in beide Richtungen still ist.

## Veröffentlichte Namen verwalten

- `juist publish` listet die veröffentlichten Namen auf und zeigt, wohin
  dieses Gerät seine eigenen weiterleitet. `juist publish remove docs` nimmt
  einen Namen auf diesem Gerät zurück, `juist publish remove nas docs` einen
  auf einem anderen Gerät.
- `juist publish serve --stop` beendet das Bedienen, merkt sich aber, wohin
  die Namen gehen. `juist ingress serve --stop` beendet den Ingress.
- `juist network domain off` lehnt juist ab, solange ein Gerät Namen unter der
  Domain veröffentlicht, und nennt das `juist publish remove`, das zuerst
  nötig ist.
- Ein Ingress und juists eigenes TLS laufen unter Linux und FreeBSD, jeweils
  für das Standardnetz des Geräts. Unter FreeBSD lässt juist pf in Ruhe: Läuft
  es auf dem Host, entscheiden dessen eigene Regeln, ob 443 (TCP und UDP), 80
  und die Ports von per TCP veröffentlichten Namen durchkommen.

## Der Ingress

- Ein Ingress ist nie Voucher oder Exit-Node und routet kein Subnetz. Er
  kann nicht unter seinem eigenen Namen teilen und veröffentlicht nichts auf
  80, 443 oder einem Port, auf dem ein Name per TCP veröffentlicht ist, weil
  er diese Ports selbst belegt. Ein Service-Mitglied hat keine weitere Rolle.
  `juist grant` nennt die Rolle, die im Weg ist.
- Jedes Mitglied nimmt von einem Ingress nur Folgendes an: Verbindungen zu den
  Ports, die das Mitglied veröffentlicht und bedient, den Log-Abgleich,
  Antworten auf Verbindungen, die das Mitglied selbst geöffnet hat (Pings
  eingeschlossen), und ICMP-Fehler zu seinen eigenen Verbindungen. Alles
  andere vom Ingress wird verworfen.
- Der Ingress schreibt für jede Verbindung eine Zeile ins Log: Adresse und
  Port des Clients, den angefragten Namen, was daraus wurde (`spliced`,
  `not served`, `no hello`, `target unreachable`, `refused`), die Bytes in
  beide Richtungen und die Dauer. Auf Port 80 kommen Methode, Pfad, Status und
  User-Agent dazu, auf einem per TCP veröffentlichten Port der Port und der
  Name, an den er geht. Jenseits von Port 80 sieht er weder Pfad noch
  User-Agent, weil TLS erst am Gerät endet.
- Einen QUIC-Fluss protokolliert er, sobald der Fluss endet, als
  `access: quic`. Der Fluss ist mit `not proven` markiert, wenn sein Client
  nie einen Handshake abgeschlossen hat, was ein Client mit gefälschter
  Adresse nicht kann. Zeilen
  solcher Flüsse und abgewiesener QUIC-Flüsse kommen höchstens einmal pro
  Sekunde, mit der Zahl der ausgelassenen Zeilen.
- `journalctl -u juist-ingress` zeigt das Log, unter FreeBSD
  `/var/log/juist-ingress.log`. Es bleibt so lange erhalten, wie das Journal
  oder newsyslog es behält.
- Der Ingress läuft unter einem eigenen Benutzer `juist-ingress`, hat keinen
  Schlüssel des Netzes und darf juistd nur eines fragen: was veröffentlicht
  ist.
- Ist der Stand des Netzes auf dem Ingress veraltet, bedient er nichts.
  Antwortet sein juistd nicht mehr, sind die Namen innerhalb von fünfzehn
  Sekunden weg.
- `juist revoke vps ingress` (oder `service`) macht das Gerät wieder zu einem
  gewöhnlichen Mitglied, und juist warnt davor:
  `warning: vps is confined no more, now a member like any other`. Ein
  möglicherweise kompromittiertes Gerät entfernst du stattdessen mit
  `juist remove`. Ist die Ingress-Rolle weg, führst du darauf
  `juist ingress serve --stop` aus.

{{< note caution >}}
Wer den Ingress kontrolliert, kann sich ein Zertifikat für deine Namen
ausstellen lassen und öffentliche Clients abfangen, ebenso Mitglieder, die
einen Namen über ihn erreichen: auf einem anderen Port als 443, hinter
`--proxy` oder auf Geräten, die die Namen des Netzes nicht auflösen.
Mitglieder, die einen Namen auf 443 zu seinem Gerät auflösen, verbinden sich
direkt mit ihm. Diese Lücke schließt ein
CAA-Eintrag, also ein DNS-Eintrag, der festlegt, wer Zertifikate für einen
Namen ausstellen darf, hier gebunden an das ACME-Konto des Ziels.
`juist publish add NAME HOST:PORT` gibt diesen Eintrag aus. Um ihn erneut zu
sehen, führe `juist publish serve` als Operator auf dem Gerät aus: Es gibt die
CAA-Einträge der Namen aus, für die es TLS beendet, jeweils mit dem Konto.
Auch das Log des Terminators enthält sie: `journalctl -u juist-serve`, unter
FreeBSD `/var/log/juist-serve.log`, und bei einem Service-Mitglied, was es
ausgibt, in Docker `docker logs immich-juist`.
{{< /note >}}

## Fehlersuche

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
| `juist health`: `warning: another program holds port 80 on …` | Mitglieder, die `http://NAME` öffnen, landen bei diesem Programm statt bei der Umleitung auf https. Lass es nur auf den Adressen lauschen, die es bedient, und öffne den Namen bis dahin mit `https://`. |
| `juist health`: `warning: no certificate for NAME: …` | Die CA hat keines ausgestellt, aus dem genannten Grund. Meist erreicht sie NAME nicht: Das öffentliche DNS von NAME muss auf einen laufenden Ingress zeigen. Bis dahin scheitert TLS bei jedem Client. |
| `juist health`: `warning: not serving NAME, which is for members alone: OTHER reaches its service as it is, …` | OTHER geht per TCP oder ohne Proxy an denselben Dienst, dessen Clients ihn also nach NAME fragen könnten. Gib NAME einen eigenen Dienst. |
| `juist health`: `warning: not serving NAME, its service meant for members alone: the log has the name public` | Soll er nur für Mitglieder sein, führt ein Admin `juist publish add GERÄT NAME --members` aus. Soll er öffentlich sein, führst du auf dem Gerät `juist publish add NAME HOST:PORT --members=false` aus. |
| `juist health`: `warning: NAME, for members alone, is not reached from here, …` | Dieses Gerät löst die Namen des Netzes über öffentliches DNS auf, NAME führt also zum Ingress, der ihn abweist. Warum, sagt der Rest von `juist health`. |
| `another program holds port 443 on …, where juist would end TLS` | Beende dieses Programm oder veröffentliche auf einem anderen Port. |
| auf vps, `juist status`: `Ingress` zeigt `…; another program holds port 443/udp` | Ein anderes Programm, oft das HTTP/3 eines Webservers, belegt 443/udp auf dem Ingress. Browser bleiben bei TCP, bis es den Port freigibt; dann übernimmt ihn der Ingress. |
| `access: quic … refused: another name's flow from its address` | Ein Client hat sich von einem UDP-Socket aus mit Namen auf zwei Geräten verbunden, und der Ingress reicht diesen Socket nur an eines davon weiter. Browser nehmen für jede Verbindung einen eigenen Socket. |
| HTTP/3 unter Last langsamer als HTTP/2 | Die UDP-Puffer des Hosts sind klein: `sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000` auf dem Gerät, das TLS beendet. |
| `another program holds port 25565 on …, where juist would pass NAME by TCP` | Der Dienst lauscht auf allen Adressen, auch auf den Overlay-Adressen des Geräts. Veröffentliche stattdessen seinen Port, wie der Hinweis sagt, und stimme mit `juist publish serve` zu. |
| auf vps, `juist status`: `Ingress` zeigt `…; another program holds port 22` | Ein Programm auf dem Ingress, oft sein sshd, belegt einen Port, auf dem ein Name per TCP veröffentlicht ist. juist überlässt ihn dann diesem Programm und den Regeln der Firewall. Veröffentliche den Namen mit `--tcp=PORT` auf einem anderen Port. |
| `this device publishes a port already` | Ein anderes `juist publish PORT` läuft, vielleicht im Hintergrund: `juist share` listet es, `juist share --stop PORT` beendet es. |
| `this device holds 16 shares already` | `juist share` listet sie; beende eine mit `juist share --stop`. |
| `this device is no ingress` | Ein Admin führt `juist grant GERÄT ingress` aus. |
| `warning: the network has no ingress, so nothing reaches it from the internet` | Gib einem Gerät mit öffentlicher Adresse die Rolle `ingress`. |
| `warning: nothing answers on 127.0.0.1:8000 yet` | Starte den Webserver, auf den `juist publish 8000` zeigt. |
| `warning: firewalld blocks tcp/443 on juist0, …` | `juist0` liegt nicht in der firewalld-Zone `trusted`, in die das Paket es nur bei der ersten Installation legt. Führe den `firewall-cmd`-Befehl aus dem Hinweis aus. |

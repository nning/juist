---
title: Zugriffsregeln
linkTitle: Zugriffsregeln
description: Festlegen, welches Gerät zu welchem welche Verbindungen aufbauen darf, welche Exit-Nodes und Subnetze es nutzen darf, und den Rest des Netzes voneinander trennen.
lead: Ohne Zugriffsregeln darf jedes Gerät zu jedem anderen jede Verbindung aufbauen. Mit ihnen bauen Geräte untereinander nur die Verbindungen auf, die eine Regel durchlässt. Alles andere wird abgewiesen.
---

## Worum es geht

Die Zugriffsregeln stehen im Log des Netzes, der signierten Liste aller
Änderungen ([So funktioniert juist]({{< relref "docs/how-it-works" >}})).
Ein Admin, also eine Person, deren Schlüssel Änderungen bestätigt, legt sie
fest, und von da an setzt jedes Gerät sie durch.

Eine Regel lässt Verbindungen durch:

```text
pass from laptop to nas proto tcp port 445
```

Damit darf laptop Verbindungen zu Port 445 auf nas aufbauen, und nas darf
darauf antworten. Umgekehrt darf nas zu laptop keine Verbindung aufbauen. Was keine
Regel durchlässt, wird abgewiesen. Regeln, die etwas sperren, gibt es nicht,
und auf die Reihenfolge kommt es nicht an.

Die Zugriffsregeln legen auch fest, wer einen [Exit-Node]({{< relref "docs/exit-nodes" >}})
nutzen oder ein [Subnetz]({{< relref "docs/subnets" >}}) erreichen darf. Wer
diese Dienste anbieten darf, bestimmen weiterhin die Rollen:
`juist grant vps exit` macht vps zum Exit-Node, und die Zugriffsregeln sagen,
welche Geräte ihren Internetverkehr darüber schicken dürfen.

## Zugriffsregeln festlegen

Angenommen, im Netz sind zwei Laptops, ein Telefon, ein NAS zu Hause und ein
VPS, der Exit-Node und Relay des Netzes ist. Die Laptops sollen das NAS per
ssh und SMB erreichen und anpingen können, das Telefon seine Fotos auf Port
443. Die Laptops gehen über den VPS ins Internet, und nur laptop darf sich
dort anmelden.

{{< step on="dem Gerät eines Admins" >}}
Schreib die Zugriffsregeln in eine Datei, `policy.conf`:

```text
table <laptops> { laptop, laptop2 }

pass from <laptops> to nas proto icmp proto tcp port { 22, 445 }
pass from phone to nas proto tcp port 443
pass from <laptops> to internet via vps
pass from laptop to vps proto tcp port 22

test pass from laptop2 to nas proto tcp port 445
test block from nas to laptop
test block from phone to laptop
```

Die `test`-Zeilen sagen, was durchgelassen und was abgewiesen werden muss.
Sie werden mit den Zugriffsregeln gespeichert, und solange ein Test
fehlschlägt, werden die Zugriffsregeln nicht übernommen.
{{< /step >}}

{{< step on="dem Gerät eines Admins" >}}
Prüf die Datei gegen das Netz und leg sie dann fest:

```console
$ juist policy check policy.conf
policy.conf: passes its 3 tests
$ juist policy set policy.conf
anything the policy does not pass is then refused; set it? [y/N] y
access policy set: 4 rules
```

Nachgefragt wird nur beim ersten Mal; in einem Skript antwortet `--yes`.

Braucht eine Änderung mehr als einen Admin, wartet sie als `policy.rec` auf
die anderen ([Mehrere Admins]({{< relref "docs/admins" >}})).
{{< /step >}}

{{< step on="laptop2" >}}
`juist devices` zeigt jetzt laptop2, nas und vps und endet mit:

```console
hint: 2 more devices the access policy keeps apart from this one: juist devices --all
```

Keine Regel verbindet laptop2 mit laptop oder dem Telefon, also hat es zu
keinem der beiden einen Tunnel. Nach `juist exit use vps` geht laptop2 über
vps ins Internet, und wo systemd-resolved läuft, auch sein DNS.
{{< /step >}}

`juist policy` zeigt die Zugriffsregeln des Netzes. `juist policy edit` öffnet
sie in `$VISUAL` oder `$EDITOR`, ist keine der beiden gesetzt, in vi, und
übernimmt, was du speicherst, sobald es sich lesen lässt und seine Tests
besteht.
`juist policy off` nimmt die Zugriffsregeln zurück: Danach darf wieder jedes
Gerät zu jedem anderen jede Verbindung aufbauen.

## Die Sprache

Die Zugriffsregeln sind in der Sprache des Filterteils von pf geschrieben,
dem Paketfilter der BSDs:

- `table <name> { laptop, phone, <andere> }` fasst Geräte und Tabellen zu
  einer Gruppe zusammen.
- `service web = proto tcp port { 80, 443 }` gibt Ports einen Namen.
- `pass from QUELLE to ZIEL`, danach bei Bedarf `proto`, `port` und `service`.

Eine Quelle ist ein Gerät, eine `<tabelle>`, `any` für alle Geräte oder
mehrere davon in geschweiften Klammern. Ein Ziel ist eines davon oder:

- `internet`, über jeden Exit-Node, oder `internet via vps`, über ein
  bestimmtes Gerät oder eine Tabelle;
- eine Adresse oder ein Präfix hinter einem Subnet-Router, etwa
  `192.168.1.0/24` oder `192.168.1.20`.

`proto` nimmt `tcp`, `udp`, `icmp` oder eine Liste in Klammern, `port` einen
Port, einen Bereich wie `8000:8080` oder eine Liste. Eine Regel kann mehrere
`proto`-Angaben enthalten. Eine Regel ohne `proto`, `port` und `service`
lässt alles durch. Für Ping braucht es `proto icmp` oder eine Regel ohne
Protokoll.

Ein Test beginnt mit `test pass` oder `test block` und prüft eine Verbindung
von einem Gerät zu einem Gerät, zu `internet via` einem Exit-Node oder zu
einer Adresse. Mit Protokoll und Port fragt er nach genau dieser Verbindung,
mit einem Protokoll allein nach irgendeinem Port davon, ohne beides danach, ob
überhaupt etwas durchgeht. `proto tcp` in einer Regel dagegen lässt jeden
TCP-Port durch.

Ein Gerätename, der ein Schlüsselwort der Sprache ist, etwa `test`, steht in
doppelten Anführungszeichen: `"test"`. Eine Regel geht über das Zeilenende
hinaus innerhalb geschweifter Klammern weiter, oder wie in pf nach einem `\`.
Kommentare gibt es nicht, `#` ist ein Fehler: Das Log hält die Regeln fest,
nicht ihren Text. Warum eine Regel da ist, gehört in die Commit-Nachricht.

`juist policy fmt` gibt eine Datei in der Form aus, in der auch
`juist policy` die Zugriffsregeln zeigt: Listen sortiert, Tabellen, Dienste, Regeln
und Tests jeweils als eigener Block. Ein Netz braucht der Befehl dafür nicht.

## Was die Zugriffsregeln bewirken

- Jedes Gerät setzt die Zugriffsregeln für das durch, was bei ihm ankommt, und merkt
  sich die Verbindungen, die es durchgelassen hat, damit die Antworten
  zurückkommen. Auch ein Gerät, das die Zugriffsregeln missachtet, kommt also nicht
  durch. Außerdem verwirft jedes Gerät, was es selbst nicht aufbauen darf.
- Ein Exit-Node leitet für ein Gerät nur weiter, was die Zugriffsregeln ihm
  erlauben. Darf ein Gerät einen Exit-Node nutzen, darf es auch dessen DNS
  fragen. Ein Subnet-Router hält es mit seinem Subnetz genauso.
- Ein [Service-Mitglied]({{< relref "docs/publishing" >}}) öffnet nichts,
  egal was die Zugriffsregeln sagen. Eine Ingress erreicht, was auf einem Gerät
  veröffentlicht ist, ebenfalls unabhängig von den Regeln.
- Zwei Geräte, die keine Regel in irgendeiner Richtung verbindet, sind keine
  Peers: Sie haben keinen Tunnel zueinander, und keines erfährt, wo das
  andere erreichbar ist. `juist devices`, `juist status` und die Namen
  `GERÄT.NETZ.juist` zeigen ein Gerät selbst und seine Peers.
- Relays und Voucher erreichen jedes Gerät für juists eigenen Verkehr, denn
  sie tragen das Log weiter. In einem Netz ohne beides behalten je zwei
  Geräte einen Tunnel, nur für juists eigenen Verkehr.
- Ein Gerät, dessen Stand des Netzes veraltet ist, behält wie ohne Regeln
  nur Tunnel zu Vouchern und lässt darüber nur juists eigenen Verkehr durch
  ([Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)).

## Warum eine Verbindung nicht durchkommt

Was die Zugriffsregeln abweisen, wird ohne Antwort verworfen: Eine
Verbindung hängt also, bis sie abbricht. Ein Gerät, das die Zugriffsregeln
von diesem getrennt halten, lässt sich als `GERÄT.NETZ.juist` gar nicht
auflösen.
`juist policy test` sagt, was die Zugriffsregeln aus einer Verbindung machen
und welche Regel sie durchlässt:

```console
$ juist policy test from laptop to nas proto tcp port 445
passes: pass from <laptops> to nas proto icmp proto tcp port { 22, 445 }
$ juist policy test from laptop to nas proto tcp port 8080
refused: no rule passes it
hint: laptop may open on nas: proto icmp proto tcp port { 22, 445 }
```

Der Befehl nimmt, was eine `test`-Zeile nimmt, und endet mit Status 1, wenn
keine Regel durchlässt.

## Was die Zugriffsregeln nicht verbergen

Das Log bleibt auf jedem Gerät vollständig: Name, Schlüssel und Adresse im
Netz jedes Geräts, die Rollen und auch die Zugriffsregeln selbst. Jedes
Mitglied kann sie mit `juist policy` ganz lesen. Die Regeln verhindern
Verbindungen und verbergen vor Geräten, die keine Peers sind, wo ein Gerät
erreichbar ist. Welche Geräte zum Netz gehören, bleibt kein Geheimnis.

## Die Regeln in git pflegen {#git}

Die Datei kann in einem Repository liegen und per Merge-Request geändert
werden:

- Die CI führt `juist policy fmt -l policy.conf` aus. Ist die Datei nicht in
  der Form von `juist policy`, nennt der Befehl sie und schlägt fehl.
  `juist policy fmt -w` schreibt sie in diese Form um.
- `juist policy check policy.conf` liest die Datei gegen das Netz und führt
  ihre Tests aus. Dafür braucht es das Log des Netzes, der Befehl läuft also
  auf einem Gerät im Netz.
- Nach dem Merge führt ein Admin `juist policy set policy.conf` aus. Braucht
  die Änderung weitere Admins, geht `policy.rec` an sie, und
  `juist approve policy.rec` zeigt die Änderung als Diff gegen die geltenden
  Regeln, samt jedem Test, den sie nicht besteht.
- `juist policy diff policy.conf` zeigt beide in der Form von
  `juist policy`: `- ` vor einer Zeile, die nur die Zugriffsregeln des Netzes
  haben, `+ ` vor einer, die nur die Datei hat, die gemeinsamen eingerückt.
  Unterscheiden sie sich, endet der Befehl mit Status 1. So fällt eine
  Änderung auf, die jemand mit `juist policy edit` gemacht hat und die nicht
  in git steht. Ist ein Gerät seitdem entfernt oder umbenannt, schlägt der
  Befehl an der Zeile der Datei fehl, die es nennt.

Gib keinem CI-Job einen Admin-Schlüssel, der allein das Quorum erreicht.
Sonst könnte jeder, der ins Repository pushen darf, das Netz ändern.

## Gut zu wissen

- `juist policy set` weist eine leere Datei ab; `juist policy off` nimmt die
  Zugriffsregeln zurück. Mit `pass from any to any` darf jedes Gerät zu jedem
  anderen jede Verbindung aufbauen, aber keine Exit-Nodes oder Subnetze
  nutzen.
- Unter Zugriffsregeln gibt `juist invite` aus:
  `hint: the access policy passes phone nothing until it names it: juist policy edit`.
- `juist policy check` und `set` warnen vor dem, was so nicht funktionieren
  kann oder ungenutzt bleibt: ein Exit-Node ohne die Rolle, ein Präfix, das
  kein Subnet-Router routet, die Adresse eines Geräts statt seines Namens,
  ein Service-Mitglied oder eine Ingress als Quelle, ein Gerät, das in keiner
  Regel vorkommt, ein Exit-Node oder Subnet-Router, den keine Regel nutzt,
  eine Tabelle oder ein Dienst, den keine Regel nutzt.
- `juist policy set -` liest die Zugriffsregeln von der Standardeingabe.
- `juist log` listet jede Änderung der Zugriffsregeln auf, und wer sie
  bestätigt hat; `juist log show N` zeigt eine davon als Diff.
- Ein entferntes Gerät fällt aus allen Regeln heraus, und eine Regel oder
  ein Test, dem es dann fehlt, entfällt; `juist remove` sagt, was die
  Zugriffsregeln dabei verlieren.
- `juist devices --all` listet auch die Geräte, die die Zugriffsregeln von
  diesem getrennt halten. Ein Admin braucht das, um sie umzubenennen oder zu
  entfernen.

## Wenn etwas nicht klappt

| Was du siehst | Was du tun kannst |
|---|---|
| `juist: the network predates access policies` | Aktualisiere juist auf allen Geräten und führe dann `juist log upgrade` aus. |
| `juist: policy.conf:3: no device "nobody" in "home"` | Korrigiere den Namen; `juist devices --all` listet die Geräte auf, und `juist log` sagt, ob eines umbenannt oder entfernt wurde. |
| `policy.conf:9: fails: test block from nas to laptop: pass from any to any passes it` | Ändere die Regel, die das durchlässt, oder den Test. |
| `juist: policy.conf:1: a policy has no comments: …` | Entferne den Kommentar und schreib die Begründung in die Commit-Nachricht. |
| `juist: …: "test" is a word of the policy's; the device goes in double quotes: "test"` | Setz den Gerätenamen in doppelte Anführungszeichen. |
| ssh oder SMB hängt und bricht dann ab | `juist policy test from laptop to nas proto tcp port 22` sagt, ob die Zugriffsregeln das durchlassen. |
| `nas.home.juist` lässt sich nicht auflösen | Keine Regel verbindet dieses Gerät mit nas; `juist policy test from laptop to nas`. |
| Ping klappt nicht, ssh schon | Ergänze die Regel um `proto icmp`. |
| `juist status`: `Exit node` zeigt `vps, internet refused: the access policy does not let this device use it` | Ergänze eine Regel `pass from … to internet via vps`. |
| `juist subnet`: `not in use: the access policy passes none of it to this device` | Ergänze eine Regel für eine Adresse oder ein Präfix im Subnetz. |

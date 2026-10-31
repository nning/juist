---
title: Zugriffsregeln
linkTitle: Zugriffsregeln
description: Festlegen, welches Gerät zu welchem auf welchen Ports Verbindungen aufbauen darf, welche Exit-Nodes und Subnetze es nutzen darf, und den Rest des Netzes voneinander trennen.
lead: Ohne Zugriffsregeln darf jedes Gerät zu jedem anderen jede Verbindung aufbauen. Mit ihnen bauen Geräte untereinander nur die Verbindungen auf, die eine Regel durchlässt. Alles andere wird abgewiesen.
---

## Wie Regeln wirken

Die Zugriffsregeln stehen im
[Mitgliederlog]({{< relref "docs/how-it-works" >}}#the-membership-log) des
Netzes. Ein Admin legt sie fest wie jede andere Änderung, und von da an setzt
jedes Gerät sie durch.

Jede Regel lässt Verbindungen durch. Diese hier:

```text
pass from laptop to nas proto tcp port 445
```

erlaubt laptop, Verbindungen zu Port 445 auf nas aufzubauen, und nas, darauf
zu antworten. Umgekehrt darf nas zu laptop keine Verbindung aufbauen. Was
keine Regel durchlässt, wird abgewiesen. Regeln, die etwas sperren, gibt es
nicht, und auf die Reihenfolge der Regeln kommt es nicht an.

Die Zugriffsregeln legen auch fest, wer einen [Exit-Node]({{< relref "docs/exit-nodes" >}})
nutzen oder ein [Subnetz]({{< relref "docs/subnets" >}}) erreichen darf. Wer
diese Dienste anbieten darf, bestimmen weiterhin die Rollen:
`juist grant vps exit` macht vps zum Exit-Node, und die Zugriffsregeln sagen,
welche Geräte ihren Internetverkehr darüber schicken dürfen.

## Zugriffsregeln festlegen

Angenommen, im Netz sind zwei Laptops, ein Telefon, ein NAS zu Hause und ein
VPS, der Exit-Node und Relay des Netzes ist. Beide Laptops sollen das NAS per
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

juist fragt nur vor den ersten Zugriffsregeln nach; in einem Skript
antwortet `--yes`. Braucht eine Änderung mehr als einen Admin, wartet sie
als `policy.rec` auf die anderen ([Mehrere Admins]({{< relref "docs/admins" >}})).
{{< /step >}}

{{< step on="laptop2" >}}
`juist devices` zeigt jetzt laptop2, nas und vps und endet mit:

```console
hint: 2 more devices the access policy keeps apart from this one: juist devices --all
```

Keine Regel verbindet laptop2 mit laptop oder dem Telefon, also hat es zu
keinem der beiden einen Tunnel. Nach `juist exit use vps` geht laptop2 über
vps ins Internet, und auch sein DNS geht über vps.
{{< /step >}}

`juist policy` zeigt die Zugriffsregeln des Netzes. `juist policy edit` öffnet
sie in `$VISUAL` oder `$EDITOR`, oder in vi, wenn keine der beiden Variablen
gesetzt ist. Beim Speichern übernimmt es die neuen Regeln, sofern sie sich
lesen lassen und ihre Tests bestehen. `juist policy off` nimmt die
Zugriffsregeln zurück: Danach darf wieder jedes Gerät zu jedem anderen jede
Verbindung aufbauen.

## Die Regelsprache

Die Zugriffsregeln sind in der Sprache der Filterregeln von pf geschrieben,
dem Paketfilter der BSDs:

- `table <name> { laptop, phone, <andere> }` fasst Geräte und Tabellen zu
  einer Gruppe zusammen.
- `service web = proto tcp port { 80, 443 }` gibt Ports einen Namen.
- `pass from QUELLE to ZIEL`, danach bei Bedarf `proto`, `port` und `service`.

Eine Quelle ist ein Gerät, eine `<tabelle>`, `any` für alle Geräte oder
mehrere davon in geschweiften Klammern. Ein Ziel ist eines davon oder:

- `internet`, über einen beliebigen Exit-Node, oder `internet via vps`, über
  ein bestimmtes Gerät oder eine Tabelle;
- eine Adresse oder ein Präfix hinter einem Subnet-Router, etwa
  `192.168.1.0/24` oder `192.168.1.20`;
- `name photos`, ein veröffentlichter Name, angegeben über sein Label unter
  der Domain des Netzes, oder `name @` für die Domain selbst. Die Regel öffnet
  Port 443, TCP und UDP, auf dem Gerät, das den Namen veröffentlicht, und nur
  für diesen Namen. Eine Regel mit `name` hat kein weiteres Ziel und keinen
  Port. [Namen nur für Mitglieder]({{< relref "docs/members-only" >}})
  brauchen eine solche Regel: Eine Regel zu ihrem Gerät oder zu `any` öffnet
  den Port, aber nicht den Namen. Veröffentlicht später ein anderes Gerät den
  Namen, folgt die Regel ihm.

`proto` nimmt `tcp`, `udp`, `icmp` oder eine Liste in Klammern, `port` einen
Port, einen Bereich wie `8000:8080` oder eine Liste. Eine Regel kann mehrere
`proto`-Angaben enthalten. Eine Regel ohne `proto`, `port` und `service`
lässt alles durch. Für Ping braucht es `proto icmp` oder eine Regel ohne
Protokoll.

Ein Test beginnt mit `test pass` oder `test block`. Er prüft eine Verbindung
von einem Gerät zu einem Ziel: einem Gerät, `internet via` einem Exit-Node,
einer Adresse oder einem Namen ohne Port. Mit Protokoll und Port prüft er
genau diese Verbindung, nur mit Protokoll einen beliebigen Port davon, ohne
beides, ob überhaupt etwas durchgeht. `proto tcp` in einer Regel lässt
dagegen jeden TCP-Port durch.

Ein Gerätename, der ein Schlüsselwort der Sprache ist, etwa `test`, steht in
doppelten Anführungszeichen: `"test"`. Innerhalb geschweifter Klammern und,
wie in pf, nach einem `\` geht eine Regel in der nächsten Zeile weiter.
Kommentare gibt es nicht, `#` ist ein Fehler: Das Log speichert die Regeln,
nicht ihren Text. Warum eine Regel da ist, gehört in die Commit-Nachricht.

`juist policy fmt` gibt eine Datei in der Standardform aus, in der auch
`juist policy` die Zugriffsregeln zeigt: Listen sortiert, Tabellen, Dienste,
Regeln und Tests jeweils als eigener Block. Ein Netz braucht der Befehl
dafür nicht.

## Wie Geräte die Regeln durchsetzen

- Jedes Gerät setzt die Zugriffsregeln für den Verkehr durch, der bei ihm
  ankommt, und merkt sich die Verbindungen, die es durchgelassen hat, damit
  die Antworten zurückkommen. Auch ein Gerät, das die Zugriffsregeln
  missachtet, kommt also nicht durch. Außerdem verwirft jedes Gerät
  ausgehenden Verkehr, den es selbst nicht aufbauen darf.
- Ein Exit-Node leitet für ein Gerät nur weiter, was die Zugriffsregeln
  durchlassen. Darf ein Gerät einen Exit-Node nutzen, darf es auch dessen DNS
  nutzen. Ein Subnet-Router hält es mit seinem Subnetz genauso.
- Ein [Service-Mitglied]({{< relref "docs/service-member" >}}) öffnet nichts,
  egal was die Zugriffsregeln sagen. Ein Ingress erreicht, was auf einem
  Gerät veröffentlicht ist, ebenfalls unabhängig von den Regeln.
- Zwei Geräte, die keine Regel in irgendeiner Richtung verbindet, sind keine
  Peers: Sie haben keinen Tunnel zueinander, und keines erfährt, wo das
  andere erreichbar ist. `juist devices`, `juist status` und die Namen
  `GERÄT.NETZ.juist` zeigen nur das Gerät selbst und seine Peers.
- Relays und Voucher erreichen jedes Gerät für juists eigenen Verkehr, denn
  sie tragen das Log weiter. In einem Netz ohne beides hat jedes Gerätepaar
  einen Tunnel, aber nur für juists eigenen Verkehr.
- Ein Gerät, dessen Stand des Netzes veraltet ist, behält wie ohne Regeln
  nur Tunnel zu Vouchern und lässt darüber nur juists eigenen Verkehr durch
  ([Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)).

## Warum eine Verbindung nicht durchkommt

Was die Zugriffsregeln abweisen, wird ohne Antwort verworfen: Eine
Verbindung hängt also, bis sie abbricht. Ein Gerät, das die Zugriffsregeln
von diesem getrennt halten, lässt sich als `GERÄT.NETZ.juist` gar nicht
auflösen. `juist policy test` sagt, was die Zugriffsregeln mit einer
Verbindung machen und welche Regel sie durchlässt:

```console
$ juist policy test from laptop to nas proto tcp port 445
passes: pass from <laptops> to nas proto icmp proto tcp port { 22, 445 }
$ juist policy test from laptop to nas proto tcp port 8080
refused: no rule passes it
hint: laptop may open on nas: proto icmp proto tcp port { 22, 445 }
```

Der Befehl nimmt dieselben Angaben wie eine `test`-Zeile und endet mit
Status 1, wenn keine Regel die Verbindung durchlässt.

## Was die Zugriffsregeln nicht verbergen

Jedes Gerät hat das vollständige Log: Name, Schlüssel und Adresse im Netz
jedes Geräts, die Rollen und auch die Zugriffsregeln selbst. Jedes Mitglied
kann sie mit `juist policy` vollständig lesen. Die Regeln verhindern
Verbindungen und verbergen vor Geräten, die keine Peers sind, wo ein Gerät
erreichbar ist. Welche Geräte zum Netz gehören, verbergen sie nicht.

## Die Regeln in git pflegen {#git}

Die Datei kann in einem Repository liegen und per Merge-Request geändert
werden:

- Die CI führt `juist policy fmt -l policy.conf` aus. Ist die Datei nicht in
  der Standardform, nennt der Befehl sie und schlägt fehl.
  `juist policy fmt -w` schreibt sie in diese Form um.
- `juist policy check policy.conf` prüft die Datei gegen das Netz und führt
  ihre Tests aus. Dafür braucht es das Log des Netzes, der Befehl läuft also
  auf einem Gerät im Netz.
- Nach dem Merge führt ein Admin `juist policy set policy.conf` aus. Braucht
  die Änderung weitere Admins, geht `policy.rec` an sie, und
  `juist approve policy.rec` zeigt die Änderung als Diff gegen die geltenden
  Regeln, samt jedem Test, den sie nicht besteht.
- `juist policy diff policy.conf` zeigt beide in der Standardform: `- ` vor
  einer Zeile, die nur die Zugriffsregeln des Netzes haben, `+ ` vor einer,
  die nur die Datei hat, die gemeinsamen eingerückt. Unterscheiden sie sich,
  endet der Befehl mit Status 1. So fällt eine Änderung auf, die jemand mit
  `juist policy edit` gemacht hat und die nicht in git steht. Ist ein Gerät
  aus der Datei seitdem entfernt oder umbenannt worden, schlägt der Befehl
  an der Zeile fehl, die es nennt.

Gib keinem CI-Job einen Admin-Schlüssel, der allein das Quorum erreicht.
Sonst könnte jeder, der ins Repository pushen darf, das Netz ändern.

## Gut zu wissen

- `juist policy set` weist eine leere Datei ab; zurücknehmen kannst du die
  Zugriffsregeln mit `juist policy off`. Mit `pass from any to any` darf jedes
  Gerät zu jedem anderen jede Verbindung aufbauen, aber keine Exit-Nodes,
  Subnetze oder Namen nur für Mitglieder nutzen.
- Gibt es Zugriffsregeln, meldet `juist invite`:
  `hint: the access policy passes phone nothing until it names it: juist policy edit`.
- `juist policy check` und `set` warnen vor allem, was so nicht funktionieren
  kann oder etwas ungenutzt lässt: ein Exit-Node ohne die Exit-Rolle, ein
  Präfix, das kein Subnet-Router routet, die Adresse eines Geräts statt
  seines Namens, ein Service-Mitglied oder ein Ingress als Quelle, ein
  Gerät, das in keiner Regel vorkommt, ein Exit-Node oder Subnet-Router, den
  keine Regel nutzt, und eine Tabelle oder ein Dienst, den keine Regel nutzt.
- `juist policy set -` liest die Zugriffsregeln von der Standardeingabe.
- `juist log` listet jede Änderung der Zugriffsregeln auf und wer sie
  bestätigt hat; `juist log show N` zeigt eine davon als Diff.
- Ein entferntes Gerät fällt aus allen Regeln heraus. Eine Regel, der danach
  Quelle oder Ziel fehlt, entfällt, ebenso jeder Test, der das Gerät nennt.
  `juist remove` sagt, was die Zugriffsregeln dabei verlieren.
- `juist devices --all` listet auch die Geräte, die die Zugriffsregeln von
  diesem getrennt halten. Ein Admin braucht das, um sie umzubenennen oder zu
  entfernen.

## Fehlersuche

| Was du siehst | Was du tun kannst |
|---|---|
| `juist: policy.conf:3: no device "nobody" in "home"` | Korrigiere den Namen; `juist devices --all` listet die Geräte auf, und `juist log` sagt, ob eines umbenannt oder entfernt wurde. |
| `policy.conf:9: fails: test block from nas to laptop: pass from any to any passes it` | Ändere die Regel, die das durchlässt, oder den Test. |
| `juist: policy.conf:1: a policy has no comments: …` | Entferne den Kommentar und schreib die Begründung in die Commit-Nachricht. |
| `juist: …: "test" is a word of the policy's; the device goes in double quotes: "test"` | Setz den Gerätenamen in doppelte Anführungszeichen. |
| ssh oder SMB hängt und bricht dann ab | `juist policy test from laptop to nas proto tcp port 22` sagt, ob die Zugriffsregeln das durchlassen. |
| `nas.home.juist` lässt sich nicht auflösen | Keine Regel verbindet dieses Gerät mit nas; prüf das mit `juist policy test from laptop to nas`. |
| Ping klappt nicht, ssh schon | Ergänze die Regel um `proto icmp`. |
| `juist status`: `Exit node` zeigt `vps, internet refused: the access policy does not let this device use it` | Ergänze eine Regel `pass from … to internet via vps`. |
| `juist subnet`: `not in use: the access policy passes none of it to this device` | Ergänze eine Regel für eine Adresse oder ein Präfix im Subnetz. |

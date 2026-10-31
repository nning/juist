---
title: So funktioniert juist
linkTitle: So funktioniert juist
description: Die Grundideen, auf denen alle anderen Seiten aufbauen, einfach erklärt, vom Netz und seinen Geräten bis zur Frische.
lead: juist verbindet deine Geräte zu einem privaten Netz, ohne Server in der Mitte. Hier lernst du die wenigen Grundideen kennen, auf denen alle anderen Seiten aufbauen.
---

## Das Netz und seine Geräte {#network}

Ein **Netz** besteht aus deinen Geräten, die sich über verschlüsselte Tunnel
erreichen, egal wo sie gerade sind: etwa ein Laptop, ein NAS zu Hause und ein
VPS.

Jedes Gerät in einem Netz ist ein **Mitglied**. Du legst ein Netz mit
`juist create` auf einem Gerät an und holst die anderen per
[Einladung]({{< relref "docs/invites" >}}) dazu. Jedes Netz hat einen Namen,
etwa `home`. Gibst du keinen an, denkt sich juist einen aus zwei zufälligen
Wörtern aus, etwa `belfast-hazardous`.

Ein Gerät kann mehreren Netzen gleichzeitig angehören, zum Beispiel einem
privaten und einem für die Arbeit. Mehr dazu unter
[Mehrere Netze]({{< relref "docs/networks" >}}).

## Zwei Programme: juist und juistd {#programs}

juist besteht aus zwei Programmen.

`juistd` ist der Daemon. Er läuft auf jedem Gerät im Hintergrund, verwahrt die
Schlüssel des Geräts und seine Kopie des Logs und hält die Tunnel aufrecht.
Unter Linux startet das Paket ihn gleich bei der Installation. Er wartet dann,
bis du ein Netz anlegst oder einem beitrittst.

`juist` ist der Befehl, den du eintippst. Er gibt juistd Aufträge und
verwahrt deine Admin-Schlüssel, falls du Admin bist.

`juist status` und `juist health` darf jeder lokale Benutzer aufrufen. Alle
anderen Befehle sind root vorbehalten und dem **Operator** des Geräts. Das ist
ein lokaler Benutzer, den du mit `juist set --operator` festlegst und der das
Gerät dann ohne sudo verwalten kann. Mehr dazu unter
[Der Operator]({{< relref "docs/operator" >}}).

## Das Mitgliederlog {#the-membership-log}

Wer zum Netz gehört, steht im **Mitgliederlog**. Das ist eine Liste
signierter Änderungen wie „nas aufnehmen“ oder „phone entfernen“. Jede
Änderung ist mit der vorigen verkettet. Niemand kann deshalb die Geschichte
umschreiben oder umsortieren, ohne dass es auffällt.

Jedes Gerät hat eine eigene Kopie des Logs und prüft jede Änderung selbst.
Dabei vertraut es weder dem Gerät, von dem die Änderung kam, noch dem Weg,
auf dem sie kam. Eine Änderung gilt erst, wenn genug Admins sie signiert
haben.

`juist log` listet die Änderungen auf und zeigt zu jeder, wer sie bestätigt
hat.

Damit das Log nicht endlos wächst, hält juist etwa alle 256 Änderungen einen
**Checkpoint** fest: den ganzen Stand des Netzes als eine Änderung. Jedes
Gerät gleicht ihn mit seiner eigenen Kopie ab, und ältere Teile des Logs
fallen weg, sobald alle Geräte ihn haben. Wie jede Änderung braucht ein
Checkpoint das Quorum.

## Admins und das Quorum {#admins}

Ein **Admin** ist ein Mensch, der das Netz ändern darf. Er kann Geräte
aufnehmen und entfernen, Rollen vergeben oder das Netz umbenennen. Wer
`juist create` aufruft, wird der erste Admin.

Änderungen signiert ein Admin mit seinem Admin-Schlüssel. Die Schlüssel
liegen im **Keystore** des Admins, `~/.config/juist` in seinem
Home-Verzeichnis, auf jedem Rechner, von dem aus er bestätigt. juistd bekommt
sie nie. Ein Schlüssel verlässt seinen Rechner nur als Sicherungszeile. Wer
zwei Laptops hat, hat also auf jedem einen eigenen.

Das **Quorum** legt fest, wie viele Admin-Stimmen eine Änderung braucht.
Voreingestellt ist 1. Nach `juist admins quorum 2` braucht jede Änderung zwei
Stimmen, zum Beispiel von zwei Personen. Fehlen noch Stimmen, wartet die
Änderung, bis andere Admins sie mit `juist approve` bestätigen. Mehr dazu
unter [Admins]({{< relref "docs/admins" >}}).

## Rollen {#roles}

Jedes Mitglied kann jedes andere erreichen, sofern
[Zugriffsregeln]({{< relref "docs/access" >}}) nichts anderes festlegen. Mit
einer **Rolle** übernimmt ein Gerät eine zusätzliche Aufgabe. Ein Admin vergibt sie mit
`juist grant DEVICE ROLE` und entzieht sie mit `juist revoke`.

| Rolle | Aufgabe des Geräts |
|---|---|
| `voucher` | Bestätigt jede Stunde, dass der Stand des Netzes aktuell ist. So merken abgeschnittene Geräte, dass ihnen etwas fehlt. Siehe [Frische](#freshness-and-vouchers) weiter unten. |
| `relay` | Leitet Verkehr zwischen Geräten weiter, die sich nicht direkt erreichen. Siehe [Relays]({{< relref "docs/relays" >}}). |
| `exit` | Leitet den Internetverkehr anderer Geräte weiter, sobald sein Operator zugestimmt hat. Siehe [Exit-Nodes]({{< relref "docs/exit-nodes" >}}). |
| `ingress` | Nimmt Verbindungen aus dem Internet für veröffentlichte Namen an. Siehe [Dienste veröffentlichen]({{< relref "docs/publishing" >}}). |
| `service` | Ein Service-Mitglied: ein eigenes juistd neben einem veröffentlichten Dienst. Kein Gerät nimmt eine Verbindung an, die es öffnet. Siehe [Service-Mitglieder]({{< relref "docs/service-member" >}}). |
| `publish` | Teilt unter dem eigenen Namen des Geräts, ohne jedes Mal einen Admin zu fragen. Siehe [Teilen]({{< relref "docs/sharing" >}}). |

Eine Rolle legt fest, welches Gerät als Exit-Node oder Relay dienen darf.
Zugriffsregeln, falls es sie gibt, legen fest, welche Geräte es nutzen dürfen.

Admin ist keine Rolle eines Geräts: Ein Admin ist ein Mensch mit Schlüsseln.
Ein Voucher ist ein Gerät und hat keinen Admin-Schlüssel.

Das LAN hinter einem Gerät machst du mit `juist subnet add` erreichbar, nicht
über eine Rolle. Mehr dazu unter [Subnet-Router]({{< relref "docs/subnets" >}}).

## Wie Geräte einander finden {#discovery}

Einen Server, der weiß, wo ein Gerät ist, gibt es nicht. Deshalb sucht juist
an drei Stellen:

- im LAN, wo sich die Geräte gegenseitig bemerkbar machen,
- bei anderen Mitgliedern, die weitergeben, wo sie ein Gerät zuletzt erreicht
  haben,
- bei den Relays des Netzes und erst danach im öffentlichen BitTorrent-DHT,
  einem großen öffentlichen Verzeichnis im Internet, falls ein Gerät ein
  Mitglied aus den Augen verloren hat.

Was die Geräte im DHT ablegen, ist verschlüsselt und gleich groß. Der DHT
sieht nur Adressen, nie Inhalte, und nichts, was er liefert, kann ändern, wer
zum Netz gehört.

## Wie Geräte sich verbinden {#connections}

Der Verkehr zwischen zwei Mitgliedern läuft durch einen WireGuard-Tunnel,
Ende zu Ende verschlüsselt. juist kommt durch NAT hindurch, sodass sich die
beiden Geräte direkt verbinden. Seine öffentliche Adresse erfragt juistd bei
öffentlichen STUN-Servern.

Erreichen sich zwei Geräte nicht direkt, geht ihr Verkehr über ein Mitglied
mit der Rolle `relay`, nie über Fremde. Das Relay sieht nur verschlüsselten
WireGuard-Verkehr.

Hinter NAT öffnest du keine Firewall-Ports. Ein Gerät mit öffentlicher
Adresse braucht 41643/udp offen. Die übrigen Ports stehen unter
[Relays]({{< relref "docs/relays" >}}), wie die Tunnel aufgebaut sind, unter
[Architektur]({{< relref "docs/architecture" >}}).

## Adressen im Netz {#addresses}

Jedes Mitglied hat zwei Adressen im Netz. `juist devices` zeigt sie an.

- Eine IPv4-Adresse, etwa `198.18.36.2`, aus einem zufälligen Block in
  `198.18.0.0/15`, den `juist create` wählt. Jedes neue Gerät bekommt die
  nächste freie. Admins können sie mit `juist network renumber` verschieben.
- Eine IPv6-Adresse wie `fd84:7a1f:97ee:21a8:2ab0:e8e:caa0:b306`, die sich
  aus dem Identitätsschlüssel des Geräts ergibt. Beim Umnummerieren bleibt sie
  gleich. Ändern kann sie nur `juist rotate identity`.

## Namen {#names}

Unter Linux und FreeBSD erreichst du jedes Mitglied unter
`DEVICE.NETWORK.juist`, etwa `laptop.home.juist`, oder einfach unter
`laptop`:

```sh
ssh laptop.home.juist
```

Gibt es Zugriffsregeln, kennt ein Gerät nur die Namen der Mitglieder, zu
denen es einen Tunnel hat. Admins können auch öffentliche Namen wie
`mail.example.org` auf Mitglieder verweisen lassen. Mehr dazu unter
[Namen]({{< relref "docs/names" >}}).

## Frische und Voucher {#freshness-and-vouchers}

Entfernt ein Admin ein Gerät, baut jedes Mitglied seinen Tunnel dorthin ab,
sobald es davon erfährt. Ein vom Rest abgeschnittenes Mitglied erfährt davon
womöglich nichts und spricht weiter mit dem entfernten Gerät.

Das begrenzt die **Frische**. Jeder **Voucher** signiert stündlich eine
Bestätigung des aktuellen Stands. Ein Mitglied mit einer solchen Bestätigung
aus den letzten 48 Stunden ist frisch. Ohne sie ist es abgelaufen und behält
nur Tunnel zu Vouchern, bis es wieder von einem hört. Ein entferntes Gerät
bleibt so höchstens 48 Stunden verbunden.

Daraus folgt:

- Ein neues Netz hat keinen Voucher und prüft keine Frische. Ein Entfernen
  erreicht trotzdem jedes Gerät, sobald es mit einem spricht, das davon weiß,
  nur ohne Zeitgrenze. `juist create --voucher` macht das erste Gerät zum
  Voucher.
- Mach nur Geräte zu Vouchern, die ständig laufen, etwa einen VPS oder einen
  Heimserver. Sind 48 Stunden lang zu wenige Voucher online, haben alle
  anderen Mitglieder nur noch Tunnel zu Vouchern. Ein Netz aus Laptops und
  Telefonen, die oft aus sind, fährt ohne Voucher besser.
- Bei nur einem Voucher vertraust du darauf, dass er ehrlich ist. Nach
  `juist admins vouchers 2` braucht ein Mitglied Bestätigungen von zwei
  Vouchern, ein einzelner lügender Voucher reicht dann nicht. Halte einen in
  Reserve: zwei von drei Vouchern auf Hosts, die unabhängig voneinander
  ausfallen, nicht zwei Maschinen beim selben Anbieter.
- Ein Relay kann ein Gerät von den anderen abschneiden. Reicht ein einziger
  Voucher, mach kein Relay zum Voucher, sonst könnte diese eine Maschine ein
  Gerät abschneiden und zugleich frisch halten.

`juist status` zeigt den Stand in der Zeile `Freshness`, zum Beispiel
`vouched just now, valid 48h`, `expired; vouchers only` oder `unchecked: no
voucher`. Einen Tag vorher warnt `juist health`: `freshness ends in 20h unless
2 vouchers vouch again`.

## Begriffe {#terms}

| Begriff | Bedeutung |
|---|---|
| Netz | Deine Geräte, die sich über juist erreichen, unter einem gemeinsamen Namen |
| Mitglied | Ein Gerät im Netz |
| juistd | Der Daemon auf jedem Gerät, verwahrt dessen Schlüssel und Log |
| juist | Der Befehl, den du eintippst |
| Operator | Der eine lokale Benutzer, der ein Gerät ohne sudo verwalten darf |
| Mitgliederlog | Die signierte Liste aller Änderungen am Netz, von jedem Gerät geprüft |
| Änderung | Ein Eintrag im Log, etwa die Aufnahme oder das Entfernen eines Geräts |
| Admin | Ein Mensch, der Änderungen signieren darf |
| Admin-Schlüssel | Der Signaturschlüssel eines Admins, im Keystore auf einem Rechner |
| Keystore | `~/.config/juist`, wo deine Admin-Schlüssel liegen |
| Quorum | Wie viele Admin-Stimmen eine Änderung braucht |
| Rolle | Eine zusätzliche Aufgabe für ein Gerät: Voucher, Relay, Exit, Ingress, Service oder Publish |
| Exit-Node | Ein Mitglied, das den Internetverkehr anderer Geräte weiterleitet, siehe [Exit-Nodes]({{< relref "docs/exit-nodes" >}}) |
| Ingress | Ein Mitglied mit öffentlicher Adresse, das Verbindungen aus dem Internet an veröffentlichte Namen weiterleitet, siehe [Dienste veröffentlichen]({{< relref "docs/publishing" >}}) |
| Service-Mitglied | Ein eigenes juistd neben einem veröffentlichten Dienst, von dem kein Gerät Verbindungen annimmt, siehe [Service-Mitglieder]({{< relref "docs/service-member" >}}) |
| Einladung | Ein Code oder Link, mit dem ein neues Gerät beitritt |
| Frische | Ob genug Voucher den Stand eines Geräts in den letzten 48 Stunden bestätigt haben |
| Voucher | Ein Gerät, das stündlich bestätigt, dass der Stand des Netzes aktuell ist |
| Relay | Ein Mitglied, das Verkehr zwischen Mitgliedern weiterleitet, die sich nicht direkt erreichen |
| Schema | Das nummerierte Format der Änderungen im Log, siehe [juist aktualisieren]({{< relref "docs/updating" >}}) |

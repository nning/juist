---
title: Umbenennen und umnummerieren
linkTitle: Umbenennen und umnummerieren
description: Dem Netz oder einem Gerät einen anderen Namen geben oder die IPv4-Adressen der Geräte verschieben, auf allen Geräten gleichzeitig.
lead: Du kannst ein Netz oder ein Gerät umbenennen und die IPv4-Adressen in einen anderen Bereich verschieben, ohne etwas neu einzurichten. Die alten Adressen funktionieren noch eine Woche lang, damit ein Gerät, das in dieser Zeit offline ist, nicht den Anschluss verliert.
---

## Worum es geht

Der Name eines Netzes ist nur eine Bezeichnung. Er steht in `juist status`,
und mit ihm sprichst du das Netz in Befehlen an. Sonst ändert ein neuer Name
nichts. Für den Namen eines Geräts gilt dasselbe, dazu kommt sein Name im DNS:
`laptop.home.juist`.

Jedes Gerät hat im Netz eine IPv4- und eine IPv6-Adresse. Beim
Umnummerieren verschiebst du die IPv4-Adressen, entweder die aller Geräte
oder die eines einzelnen. Das brauchst du, wenn der Bereich des Netzes mit
einem LAN kollidiert, das du nutzt, oder mit
[einem anderen Netz auf demselben Gerät]({{< relref "docs/networks" >}}).
IPv6-Adressen ändern sich dabei nie.

Beides sind Änderungen am Mitgliederlog, der signierten Liste aller
Änderungen, die jedes Gerät prüft
([So funktioniert juist]({{< relref "docs/how-it-works" >}})). Ein Admin
nimmt sie vor, und alle Geräte ziehen nach. Braucht das Quorum mehr als einen
Admin, wartet die Änderung auf die anderen
([Mehrere Admins]({{< relref "docs/admins" >}})).

## Das Netz umbenennen

{{< step on="dem Gerät eines Admins" >}}
```sh
juist network rename office
```

Die Ausgabe lautet `renamed "home" to "office"`, und alle Geräte übernehmen
den neuen Namen.
{{< /step >}}

## Ein Gerät umbenennen

{{< step on="dem Gerät eines Admins" >}}
```sh
juist rename phone tablet
```

Die Ausgabe lautet `renamed phone to tablet`. Danach erreichen alle Geräte es
als `tablet.home.juist`, und `phone.home.juist` löst nicht mehr auf.
Schlüssel, Adressen, Rollen und veröffentlichte Namen bleiben, wie sie waren.
{{< /step >}}

Das Gerät gibst du an wie bei `juist remove`: mit Namen, Adresse oder
Schlüssel. Einen Namen, den schon ein anderes Gerät hat, egal in welcher
Schreibweise, lehnt juist ab. Ein Gerät, das
[Dateien teilt]({{< relref "docs/publishing" >}}), teilt unter dem neuen
Namen, `tablet.pub.example.org`; deshalb lehnt juist auch einen Namen ab, den
ein anderes Gerät veröffentlicht, einen, den das Gerät selbst veröffentlicht
oder auf sich zeigen lässt, und einen, der kein DNS-Label ergibt. Ein
laufendes `juist share` gibt seinen neuen Link aus.

## Die Adressen aller Geräte verschieben

{{< step on="dem Gerät eines Admins" >}}
Verschiebe das ganze Netz in einen neuen Bereich:

```console
$ juist network renumber 10.7.0.0/22
move "home" from 198.18.36.0/22 to 10.7.0.0/22, old addresses until Fri 9 Oct 14:00? [y/N] y
moving to 10.7.0.0/22; old addresses until Fri 9 Oct 14:00
```

Jedes Gerät behält seine Position im Bereich, sofern sie frei ist: Aus
`198.18.36.2` wird `10.7.0.2`.
{{< /step >}}

{{< step on="einem beliebigen Gerät" >}}
Verfolge den Umzug:

```console
$ juist network
home
  IPv4          10.7.0.0/22, 198.18.36.0/22 until Fri 9 Oct 14:00
  IPv6          fd77:9359:d9fb::/48

MOVING  FROM         TO        OLD UNTIL
laptop  198.18.36.1  10.7.0.1  Fri 9 Oct 14:00
nas     198.18.36.2  10.7.0.2  Fri 9 Oct 14:00
```

`juist devices` zeigt für jedes Gerät die neue Adresse und dahinter die alte,
etwa `10.7.0.2 (was 198.18.36.2)`.
{{< /step >}}

Bis zum Ablauf der Frist sind die Geräte unter beiden Adressen erreichbar.
Danach gelten nur noch die neuen.

## Die Adresse eines einzelnen Geräts verschieben

```sh
juist network renumber phone 10.7.0.9
```

Damit bekommt `phone` die Adresse `10.7.0.9` innerhalb des Netzbereichs. Die
alte Adresse funktioniert wie oben bis zum Ablauf der Frist weiter.

## Alte Adressen sofort stilllegen

Haben alle Geräte vom Umzug erfahren, musst du nicht auf die Frist warten:

| Ziel | Befehl |
|---|---|
| ein Gerät verschieben und seine alte Adresse sofort stilllegen | `juist network renumber phone 10.7.0.9 --finish` |
| alle alten Adressen jetzt stilllegen | `juist network renumber --finish` |

`--finish` warnt vorher, dass Geräte, die vom Umzug noch nichts wissen, die
alte Adresse verlieren.

## Gut zu wissen

- Alte IPv4-Adressen funktionieren in der Voreinstellung noch 7 Tage. Mit
  `--for 12h` oder `--for 14d` wählst du eine andere Frist. Sie sollte lang
  genug sein, dass jedes Gerät in dieser Zeit einmal online ist.
- Die Frist steht fest, sobald die Änderung vorgeschlagen ist. Bestätigen
  andere Admins sie später, sehen sie, wie viel Zeit noch bleibt.
- Ein Gerät hat höchstens eine alte Adresse. Wird es vor Ablauf der Frist
  erneut verschoben, fällt die frühere alte Adresse sofort weg, und juist
  warnt davor.
- Stillgelegte Adressen bleiben reserviert, damit kein anderes Gerät sie
  bekommt, bis du `juist network renumber --finish` ohne weitere Argumente
  aufrufst.
- Der neue Bereich muss Platz für alle Geräte bieten. juist warnt, wenn er
  sich mit einem LAN dieses Hosts überschneidet oder mit einem anderen Netz,
  dem das Gerät angehört.
- Konfiguration außerhalb von juist, in der alte Adressen stehen, zieht nicht
  mit um. Firewall-Regeln, Einträge in `/etc/hosts` und Ähnliches musst du
  selbst anpassen.
- Mit [mehreren Netzen]({{< relref "docs/networks" >}}) auf dem Gerät gibst
  du das Netz zuerst an: `juist network renumber work 10.7.0.0/24`,
  `juist network rename work office`.
- Ein Gerätename mit `.` oder `_` ist kein DNS-Name: juist warnt, und das
  Gerät ist dann nur über seine Adresse erreichbar. Ein Gerät mit der Rolle
  `publish` kann einen solchen Namen nicht bekommen, da es unter seinem Namen
  teilt.
- Ein Admin-Schlüssel behält den Gerätenamen, unter dem er abgelegt wurde;
  `juist admins` zeigt ihn.

## Wenn etwas nicht klappt

| Was du siehst | Was du tun kannst |
|---|---|
| `juist status`: `no IPv4 on this host: …` | Zwei Netze auf diesem Gerät überschneiden sich. Nummeriere eines um, wie der Hinweis vorschlägt. |
| `juist: 10.7.0.9 is taken by nas` | Wähl eine freie Adresse. |
| `juist: 10.7.0.9 is outside the network's range …` | Wähl eine Adresse aus dem Bereich, den `juist network` anzeigt. |
| `juist: the network predates renumbering` | Sobald alle Geräte diese Version haben: `juist log upgrade`. |
| `juist: the network predates renaming a device` | Ebenso. |
| `juist: another device is named "tablet" already` | Wähl einen anderen Namen, oder benenne zuerst das andere Gerät um. |

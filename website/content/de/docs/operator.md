---
title: Ohne sudo verwalten
linkTitle: Ohne sudo verwalten
description: Einen lokalen Benutzer als Verwalter eines Geräts festlegen, damit juist-Befehle ohne sudo funktionieren.
lead: Jedes Gerät kann einen Operator haben, also einen lokalen Benutzer, der dort jeden juist-Befehl ohne sudo ausführen darf. Du legst ihn einmalig als root fest.
---

## Worum es geht

Auf jedem Gerät erledigt der Daemon `juistd` die Arbeit, und der Befehl
`juist` gibt ihm Aufträge. Der Daemon entscheidet, wer was darf:

| Wer | Darf |
|---|---|
| root | alles, auch den Operator festlegen |
| der Operator | alles andere, etwa Geräte auflisten, einladen, Änderungen bestätigen oder einen Exit-Node nutzen |
| jeder andere lokale Benutzer | nur `juist status` |

Der **Operator** ist ein lokaler Benutzer, der für dieses Gerät festgelegt
ist. Meist bist das du, also die Person, die das Gerät benutzt. Mit einem
Operator musst du nicht vor jeden Befehl `sudo` schreiben.

Für Änderungen am Netz selbst, etwa um ein Gerät aufzunehmen oder zu
entfernen, braucht es außerdem einen Admin-Schlüssel. Ein Admin ist eine
Person, deren Schlüssel Änderungen bestätigt. Admin-Schlüssel liegen in deinem
eigenen Keystore `~/.config/juist`. Deshalb führst du diese Befehle als du
selbst aus, nicht mit sudo (siehe [Admins]({{< relref "docs/admins" >}})).

## Den Operator festlegen

Meist musst du gar nichts tun:

- Führst du `juist create` als du selbst aus, fragt es einmal, ob es `sudo juist set` ausführen soll, und macht dich zum Operator.
- `sudo juist join …` macht den Benutzer, der sudo aufgerufen hat, zum Operator, es sei denn, du nennst mit `--operator` einen anderen.

Hat das Gerät noch keinen Operator oder willst du ihn ändern, geht das auch von Hand.

{{< step on="laptop" >}}
Mach deinen Benutzer zum Operator:

```sh
sudo juist set --operator=$USER
```

Die Ausgabe lautet `operator alice`. Ab jetzt funktioniert jeder
juist-Befehl auf diesem Gerät ohne sudo.
{{< /step >}}

So nimmst du das wieder zurück:

```sh
sudo juist set --operator=""
```

Die Ausgabe lautet `operator cleared`.

## Gut zu wissen

- Jedes Gerät hat pro Netz genau einen Operator. Ihn mit
  `juist set --operator` zu wählen braucht root; den Rest von `juist set`,
  etwa [nur HTTPS]({{< relref "docs/https-only" >}}), darf der Operator ändern.
- Ein Befehl, der den Operator braucht, fragt im Terminal
  `not the operator; run sudo juist set --operator=alice? [Y/n]` und führt den
  Befehl aus, wenn du zustimmst.
- Einige Befehle verändern den Rechner selbst und fragen deshalb weiterhin
  einmal nach sudo: `juist exit serve`, `juist subnet serve` und das Anlegen oder
  Beitreten eines [zweiten Netzes]({{< relref "docs/networks" >}}) auf
  demselben Gerät.
- Ist ein Gerät in mehreren Netzen, gibst du das Netz an:
  `sudo juist set work --operator=$USER`.
- `juist reset` löscht den Operator zusammen mit dem Netz.

## Wenn etwas nicht klappt

Ruft jemand `juist status` auf, der nicht Operator ist, endet die Ausgabe so:

```console
$ juist status
…
hint: read-only; to manage this device: sudo juist set --operator=alice
```

Führe diesen Befehl einmal aus. Kann ein Befehl nicht nachfragen, etwa in
einem Skript, bricht er mit `juist: operator only` und demselben Hinweis ab.

Siehe auch [Status und Geräte]({{< relref "docs/status" >}}) und
[Fehlersuche]({{< relref "docs/troubleshooting" >}}).

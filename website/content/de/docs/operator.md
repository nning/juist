---
title: Ohne sudo verwalten
linkTitle: Ohne sudo verwalten
description: Einen lokalen Benutzer als Verwalter eines Geräts festlegen, damit juist-Befehle ohne sudo funktionieren.
lead: Jedes Gerät kann einen Operator haben, also einen lokalen Benutzer, der dort jeden juist-Befehl ohne sudo ausführen darf. Du legst ihn einmal als root fest.
---

## Wer was darf

Auf jedem Gerät erledigt der Daemon `juistd` die Arbeit, und der Befehl
`juist` schickt ihm Anfragen. Der Daemon entscheidet, wer was darf:

| Wer | Darf |
|---|---|
| root | alles, auch den Operator festlegen |
| der Operator | alles andere, etwa Geräte auflisten, einladen, Änderungen bestätigen oder einen Exit-Node nutzen |
| jeder andere lokale Benutzer | nur `juist status` und `juist health` |

Der **Operator** ist der lokale Benutzer, der für dieses Gerät festgelegt
ist, meist du, also die Person, die das Gerät benutzt. Gibt es einen
Operator, musst du nicht mehr vor jeden Befehl `sudo` schreiben.

Für Änderungen am Netz selbst, etwa um ein Gerät aufzunehmen oder zu
entfernen, braucht es außerdem einen Admin-Schlüssel. Ein Admin ist eine
Person, deren Schlüssel Änderungen bestätigt. Admin-Schlüssel liegen in deinem
eigenen Keystore `~/.config/juist`. Deshalb führst du diese Befehle als du
selbst aus, nicht mit sudo (siehe [Admins]({{< relref "docs/admins" >}})).

## Den Operator festlegen

Meist musst du gar nichts tun:

- Führst du `juist create` als du selbst aus, fragt es einmal, ob es `sudo juist set` ausführen soll, und macht dich zum Operator.
- `sudo juist join …` macht den Benutzer, der sudo aufgerufen hat, zum Operator, es sei denn, du nennst mit `--operator` einen anderen.

Hat das Gerät noch keinen Operator oder willst du ihn ändern, legst du ihn von Hand fest.

{{< step on="laptop" >}}
Mach deinen Benutzer zum Operator:

```sh
sudo juist set --operator=$USER
```

Die Ausgabe lautet `operator alice`. Ab jetzt funktioniert jeder
juist-Befehl auf diesem Gerät ohne sudo.
{{< /step >}}

So entfernst du den Operator wieder:

```sh
sudo juist set --operator=""
```

Die Ausgabe lautet `operator cleared`.

## Hinweise

- Jedes Gerät hat pro Netz genau einen Operator. Nur root kann ihn mit
  `juist set --operator` festlegen. Die übrigen Einstellungen von
  `juist set`, etwa die für [Netze, die nur HTTPS durchlassen]({{< relref "docs/https-only" >}}),
  darf der Operator ändern.
- Ein Befehl, der den Operator braucht, fragt im Terminal
  `not the operator; run sudo juist set --operator=alice? [Y/n]` und führt
  den angezeigten Befehl aus, wenn du zustimmst.
- Einige Befehle verändern den Rechner selbst und fragen deshalb weiterhin
  einmal nach sudo: `juist exit serve`, `juist subnet serve` und das Anlegen oder
  Beitreten eines [zweiten Netzes]({{< relref "docs/networks" >}}) auf
  demselben Gerät.
- Ist ein Gerät in mehreren Netzen, gibst du das Netz an:
  `sudo juist set work --operator=$USER`.
- `juist reset` löscht den Operator zusammen mit dem Netz.

## Fehlersuche

Ruft jemand `juist health` auf, der nicht Operator ist, endet die Ausgabe so:

```console
$ juist health
…
hint: read-only; to manage this device: sudo juist set --operator=alice
```

Führe diesen Befehl einmal aus. Kann ein Befehl nicht nachfragen, etwa in
einem Skript, bricht er mit `juist: operator only` und demselben Hinweis ab.

Siehe auch [Status und Geräte]({{< relref "docs/status" >}}) und
[Fehlersuche]({{< relref "docs/troubleshooting" >}}).

---
title: Teilen
linkTitle: Teilen
description: Eine Datei, ein Verzeichnis oder einen lokalen Webserver sofort im Internet teilen, unter dem eigenen Namen des Geräts.
lead: Ein Gerät mit der Rolle publish teilt eine Datei, ein Verzeichnis oder einen lokalen Webserver unter seinem eigenen Namen, ohne jedes Mal einen Admin zu fragen.
status: [Linux, FreeBSD]
---

## Einrichten

Du brauchst eine Domain und einen Ingress, wie sie
[Dienste veröffentlichen]({{< relref "docs/publishing" >}}#setting-it-up)
einrichtet. Dann gibt ein Admin dem Gerät einmal die Rolle:

```sh
juist grant laptop publish
```

Der Laptop teilt danach unter `laptop.example.org`:

```sh
juist share ~/photos/2026          # unter https://laptop.example.org/ZUFALL/, bis Strg-C
juist publish 8000 --for 2h        # den Webserver dieses Geräts auf Port 8000, zwei Stunden lang
juist share -b --for 7d ~/talk.pdf # im Hintergrund, eine Woche lang
juist share                        # listet das Geteilte dieses Geräts mit Links auf
juist share --stop ~/talk.pdf      # beendet eines, über Datei, Port oder Link
```

## Was andere sehen

- Etwas Geteiltes ist nur unter seinem zufälligen Pfad erreichbar. Jeder
  andere Pfad antwortet mit 404, außer ein `juist publish PORT` bedient ihn.
  Einträge wie `.git` bleiben verborgen.
- Ein Verzeichnis erscheint als Liste, sortierbar nach Name, Größe oder
  Datum, und lädt sich als ZIP herunter, ganz oder Ordner für Ordner. Ein
  Ordner mit einer `index.html` zeigt stattdessen diese Seite.
- Ein Zertifikat für den Namen des Geräts deckt alles Geteilte ab, also
  erscheinen die Pfade nie in einem Zertifikatslog.

## Wie lange es läuft

- Teilen endet, wenn sein Befehl endet oder `--for` abläuft, nach höchstens
  sieben Tagen. Verschwindet das Gerät, endet es innerhalb von zehn Minuten.
- Mit `--background` (`-b`) kehrt der Befehl zurück, sobald das Teilen läuft.
  Es läuft dann, bis `juist share --stop` oder `--for` es beendet, unter
  demselben Link, auch über einen Neustart von juistd hinweg.
- `juist share` listet das Geteilte mit Links auf, und `juist status` zählt
  es unter `Sharing`.

## Grenzen

- Ein Gerät teilt bis zu 16 Dinge gleichzeitig, jedes unter seinem eigenen
  Pfad, dazu ein `juist publish PORT`, das jeden übrigen Pfad beantwortet.
- `juist share --stop` ohne Argument beendet das einzige Geteilte. Laufen
  mehrere, fordert es dich auf, eines zu nennen.
- Wird das Gerät [umbenannt]({{< relref "docs/network-changes" >}}), teilt es
  unter seinem neuen Namen, und `juist share` gibt den neuen Link aus.
- Geteiltes läuft nur über TCP, nicht über HTTP/3.

## Fehlersuche

| Du siehst | Was zu tun ist |
|---|---|
| `this device holds no publish role` | Ein Admin führt `juist grant DEVICE publish` aus. |
| `this device publishes a port already` | Ein anderes `juist publish PORT` läuft, vielleicht im Hintergrund. `juist share` listet es auf; `juist share --stop PORT` beendet es. |
| `this device holds 16 shares already` | `juist share` listet sie auf. Beende eines mit `juist share --stop`. |
| `warning: nothing answers on 127.0.0.1:8000 yet` | Starte den Webserver, auf den `juist publish 8000` zeigt. |
| `juist status`: `Sharing` zeigt `reached by nobody: the terminator does not run` | `juist share` startet ihn. `journalctl -u juist-serve` zeigt, warum er stoppte. |

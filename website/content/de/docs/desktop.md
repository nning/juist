---
title: Die Statusleiste unter Linux
linkTitle: Statusleiste
description: In der Statusleiste eines Linux-Desktops sehen, ob juist verbunden ist, welcher Exit-Node genutzt wird und was Aufmerksamkeit braucht, und den Exit-Node im Menü wechseln.
lead: juist tray legt ein Symbol in die Statusleiste eines Linux-Desktops. Es zeigt auf einen Blick, wie es um juist steht, und sein Menü wechselt den Exit-Node ohne Terminal.
---

## Einschalten

`juist tray` zeigt das Symbol unter Linux, solange deine Sitzung läuft. Damit
es ab jetzt mit deiner Desktop-Sitzung startet:

```sh
juist tray --autostart
```

Das legt einen Eintrag in dein eigenes Autostart-Verzeichnis
(`~/.config/autostart/juist-tray.desktop`) und startet noch nichts: Führe
einmal `juist tray` aus, um es gleich zu sehen, oder melde dich neu an. Jeder
Benutzer schaltet es für sich selbst ein; auf einem Server ändert sich
nichts. So schaltest du es wieder ab:

```sh
juist tray --autostart=false
```

## Welche Desktops es zeigen

Das Symbol ist ein StatusNotifierItem, das KDE Plasma, Xfce, Cinnamon, LXQt
und die Leisten von sway und waybar zeigen. GNOME zeigt es nur mit der
Erweiterung AppIndicator: Installiere `gnome-shell-extension-appindicator`
(Debian, Ubuntu und Fedora), schalte sie in der App „Erweiterungen“ ein und
melde dich neu an. Zeigt zehn Sekunden nach dem Start keine Statusleiste das
Symbol, sagt juist tray das in einer Benachrichtigung.

## Das Symbol

| Das Symbol | bedeutet |
|---|---|
| das juist-Logo, grau | juistd läuft nicht, oder dieses Gerät ist in keinem Netz oder nicht verbunden |
| das juist-Logo | verbunden |
| mit Pfeil oben rechts | das Internet geht über einen Exit-Node |
| mit gelbem Punkt unten rechts | `juist health` warnt |
| mit rotem Punkt unten rechts | ein Alarm, wie ihn `juist status` rot zeigt |

Zeigst du auf das Symbol, siehst du die ersten Zeilen von `juist status`.

## Das Menü

- **This device** und seine Adressen. Ein Klick kopiert den Namen oder die
  Adresse; dafür braucht es `wl-copy` (aus wl-clipboard) unter Wayland oder
  `xclip` oder `xsel` unter X11.
- **Devices**, die Geräte, zu denen dieses einen Tunnel hält, jedes damit,
  wie die letzte Prüfung es erreicht hat. Ein Klick kopiert seine Adresse.
  `juist devices` listet alle.
- **Exit node**: keiner, oder eines der Geräte mit der Rolle. Eines, das
  nicht dient, ist ausgegraut. Die Wahl führt `juist exit use` als du aus,
  mit seinen Prüfungen; wovor es warnt oder warum es ablehnt, kommt als
  Benachrichtigung.
- Wovor `juist health` warnt, falls es etwas gibt.

Auf einem Gerät in [mehreren Netzen]({{< relref "docs/networks" >}}) hat das Menü
ein Untermenü je Netz. Eine Warnung von `juist health`, die vorher nicht da
war, oder ein Alarm kommt außerdem als Benachrichtigung.

## Wer umschalten darf

Der [Operator]({{< relref "docs/operator" >}}) des Geräts bekommt das ganze
Menü. Jeder andere Benutzer sieht den Zustand, ohne die Geräte und ohne den
Schalter für den Exit-Node, so wie ihm `juist status` ihn zeigt. So machst du
dich zum Operator:

```sh
sudo juist set --operator=$USER
```

juist tray hält keine Schlüssel. Geräte einladen, zustimmen und entfernen
bleibt Sache der Kommandozeile.

## Gut zu wissen

- juist tray fragt juistd alle paar Sekunden nach seinem Zustand und führt
  `juist health` aus, wenn er sich ändert, sonst einmal pro Minute.
- Hält juistd an, wird das Symbol grau. Es kommt zurück, sobald juistd wieder
  startet, ohne dass juist tray neu starten muss.
- Pro Sitzung läuft ein juist tray; ein zweites beendet sich sofort.
- Auch die Autostart-Einstellungen des Desktops listen den Eintrag und
  können ihn dort abschalten.
- Wird juist entfernt, bleibt der Eintrag in deinem Home-Verzeichnis; ohne
  juist startet er nichts.

---
title: Installation
linkTitle: Installation
description: Das juist-Paket bauen und auf Debian, Ubuntu, Fedora oder FreeBSD installieren, oder auf einem Rechner bauen und auf einem anderen installieren.
lead: juist installierst du als Paket deines Systems, und zwar auf jedem Gerät, das in ein Netz soll. Das Paket baust du mit einem einzigen Befehl aus dem Quellcode.
---

## Worum es geht

juist läuft unter Linux und FreeBSD. Auf Debian und Ubuntu ist es ein `.deb`,
auf Fedora ein RPM und auf FreeBSD ein pkg-Paket. Fertige Pakete gibt es
nicht. Du baust das Paket aus dem Quellcode und installierst es dann. Ein
Telefon tritt stattdessen mit der App bei, siehe
[Android]({{< relref "docs/android" >}}).

Zum Bauen brauchst du Go 1.27. `make` lädt dann selbst go1.27.2 herunter und
verwendet es, damit ein Commit auf jedem Rechner exakt dasselbe Ergebnis
liefert.

## Auf diesem Gerät installieren

{{< step on="jedem Gerät" >}}
Hol dir den Quellcode:

```sh
git clone https://github.com/nning/juist
cd juist
```
{{< /step >}}
{{< step on="einem Gerät mit Debian, Ubuntu oder Fedora" >}}
Bau das Paket und installiere es:

```sh
make install
```

Auf Debian und Ubuntu entsteht so das `.deb`, auf Fedora das RPM, und beides
wird gleich mit sudo installiert.
{{< /step >}}
{{< step on="einem Gerät mit FreeBSD" >}}
Bau das Paket als root, installiere es mit pkg und starte dann den Daemon:

```sh
gmake install
sysrc juistd_enable=YES && service juistd start
```

Unter Linux startet das Paket den Daemon von selbst. Unter FreeBSD startest
du ihn einmal wie oben gezeigt.
{{< /step >}}

Rufst du `make install` später erneut auf, ersetzt der neue Build den alten.
Der Zustand des Geräts bleibt dabei erhalten.

## Das Paket für einen anderen Rechner bauen

Soll ein Rechner juist nicht selbst bauen, baust du nur das Paket und
kopierst es hinüber:

| System | Bauen | Auf dem anderen Rechner installieren |
|---|---|---|
| Debian, Ubuntu | `make deb` | `sudo apt install ./juist_*.deb` |
| Fedora | `make rpm` | `sudo dnf install ./juist-*.rpm` |
| FreeBSD | `make pkg-freebsd` | `pkg add ./juist-*.pkg` |

Die Pakete landen in `build/deb`, `build/rpm/RPMS` und `build/freebsd`.
`make deb DEB_ARCH=arm64` baut das `.deb` für eine andere Prozessorarchitektur,
mit `armhf` und `i386` funktioniert es genauso.

## Was im Paket steckt

- Der Befehl `juist` und der Daemon `juistd`. Was die beiden Programme tun,
  steht unter [So funktioniert juist]({{< relref "docs/how-it-works" >}}).
- Unter Linux der Dienst `juistd`. Er startet sofort und wartet, bis du ein
  Netz anlegst oder einem beitrittst. Er läuft unter dem eigenen Benutzer
  `juist` und hat nur `CAP_NET_ADMIN`. Daneben der Dienst `juist-ingress` für
  eine Ingress, den `juist ingress serve` startet, und `juist-serve` für juists
  eigenes TLS, den systemd ohne sudo startet, sobald `juist publish` oder
  `juist share` ihn braucht
  ([Dienste veröffentlichen]({{< relref "docs/publishing" >}})).
- Firewall-Profile für ufw und firewalld: `juist`, `juist-relay`,
  `juist-invite` und `juist-ingress`. Läuft ufw oder firewalld, lässt das
  Paket außerdem den Verkehr auf dem Netzwerkgerät `juist0` durch. Den braucht
  das Netz, um sein Log abzugleichen, und ein veröffentlichter Dienst, um
  erreicht zu werden. Das geschieht nur bei der ersten Installation, damit ein
  Upgrade die Firewall so lässt, wie du sie eingerichtet hast.
- Eine polkit-Regel, die juistd erlaubt, das DNS des Netzes über
  systemd-resolved einzurichten. Das Paket empfiehlt polkit, das die Regel
  ausführt; Minimalinstallationen wie Fedora Cloud haben es sonst nicht.
- Shell-Vervollständigung für bash, zsh und fish sowie die Man-Pages
  `juist(1)` und `juistd(8)`.

Ob der Daemon läuft, siehst du so:

```console {device="nas"}
$ juist status
nas · no network
hint: juist join CODE, or juist create
```

Weiter geht es mit dem [ersten Netz]({{< relref "docs/first-network" >}}).

## Deinstallieren

Ist das Gerät Mitglied eines Netzes, nimm es zuerst heraus, damit es dort
nicht weiter geführt wird. Dazu ruft ein Admin auf seinem eigenen Gerät
`juist remove nas` auf. Danach entfernst du das Paket:

```sh
sudo apt remove juist      # Debian, Ubuntu
sudo dnf remove juist      # Fedora
pkg delete juist           # FreeBSD, als root
```

Dabei werden alle juistd-Prozesse beendet, und alles, was juist auf dem
Rechner eingerichtet hat, wird rückgängig gemacht. Unter Linux betrifft das
die Firewall-Regel für `juist0`, eine Ingress und die Änderungen von
`juist exit serve`.

## Gut zu wissen

- Unter Linux bleiben die Schlüssel und das Log des Geräts in
  `/var/lib/juist` erhalten, ebenso die Systembenutzer `juist`,
  `juist-ingress` und `juist-serve`. Auf Debian und Ubuntu löscht
  `sudo apt purge juist` das Verzeichnis `/var/lib/juist` nur, wenn es leer
  ist. Andernfalls meldet es:
  `juist: kept /var/lib/juist, which still holds this device's keys and log`.
- Auch `/var/lib/juist-serve` bleibt, das ACME-Konto des Terminators, das die
  CAA-Einträge veröffentlichter Namen nennen, und das Entfernen sagt es:
  `juist: kept /var/lib/juist-serve, the terminator's ACME account, which CAA records may name`.
  Unter FreeBSD ist es `/var/db/juist-serve`.
- Unter FreeBSD gibt das Entfernen eine Zeile aus, die mit `juist: kept`
  beginnt und aufzählt, was erhalten bleibt.
- Deine Admin-Schlüssel in `~/.config/juist` gehören nicht zum Paket und
  bleiben beim Entfernen unberührt.
- Willst du nur ein Netz verlassen und juist behalten, nimm stattdessen
  `juist reset`. Mehr dazu unter [ein Gerät entfernen]({{< relref "docs/remove" >}}).

## Wenn etwas nicht klappt

- `make install` meldet
  `make install knows apt (Debian, Ubuntu), dnf (Fedora) and pkg (FreeBSD); use make deb, rpm or pkg-freebsd`:
  Dieses System nutzt keinen der drei Paketmanager. Bau das Paket für eines
  der unterstützten Systeme und installiere es dort.
- `juist status` meldet `juistd not running`: Starte ihn mit
  `sudo systemctl enable --now juistd`, unter FreeBSD mit `service juistd start`.
- Unter Linux zeigt `journalctl -u juistd` das Log des Daemons.

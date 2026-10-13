---
title: Installation
linkTitle: Installation
description: Das fertige juist-Paket auf Debian, Ubuntu, Fedora oder FreeBSD installieren, den Download prüfen oder das Paket aus dem Quellcode bauen.
lead: juist installierst du als Paket deines Systems, und zwar auf jedem Gerät, das in ein Netz soll. Jedes Release bringt fertige Pakete mit, dazu eine signierte Liste ihrer Prüfsummen.
---

## Unterstützte Systeme

juist läuft unter Linux und FreeBSD. Für Debian und Ubuntu gibt es ein
`.deb`, für Fedora ein RPM und für FreeBSD ein pkg-Paket. Jedes
[Release](https://github.com/nning/juist/releases/latest) enthält die Pakete
für amd64 und arm64, das RPM allerdings nur für x86_64. Ein
Telefon tritt stattdessen mit der App bei, siehe
[Android]({{< relref "docs/android" >}}).

## Das Paket installieren

{{< step on="einem Gerät mit Debian oder Ubuntu" >}}
Lade das Paket herunter und installiere es:

```sh
curl -LO https://github.com/nning/juist/releases/latest/download/juist_amd64.deb
sudo apt install ./juist_amd64.deb
```

Auf arm64 nimmst du `juist_arm64.deb`.
{{< /step >}}
{{< step on="einem Gerät mit Fedora" >}}
Installiere das Paket:

```sh
sudo dnf install https://github.com/nning/juist/releases/latest/download/juist.x86_64.rpm
```
{{< /step >}}
{{< step on="einem Gerät mit FreeBSD 14" >}}
Installiere das Paket als root mit pkg und starte dann den Daemon:

```sh
pkg add https://github.com/nning/juist/releases/latest/download/juist-freebsd14-amd64.pkg
sysrc juistd_enable=YES && service juistd start
```

Auf arm64 nimmst du `juist-freebsd14-aarch64.pkg`. Unter Linux startet das
Paket den Daemon von selbst, unter FreeBSD startest du ihn einmal wie oben
gezeigt.
{{< /step >}}

Installierst du später ein neueres Release, ersetzt es das alte. Der Zustand
des Geräts bleibt dabei erhalten.

## Den Download prüfen

Jedes Release führt die SHA-256-Summen seiner Dateien in `SHA256SUMS`,
signiert mit dem Schlüssel in
[packaging/release-signers](https://github.com/nning/juist/blob/main/packaging/release-signers).
Leg diese Datei, den Download, `SHA256SUMS` und `SHA256SUMS.sig` in ein
Verzeichnis und prüfe dann so:

```sh
ssh-keygen -Y verify -f release-signers -I juist -n juist-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

Der erste Befehl meldet `Good "juist-release" signature for juist with ED25519
key SHA256:a2nq8txrPWVfLfF4XGzyKrFo4t71aXkcDOGZNQJABLM`, der zweite `OK` für
jede heruntergeladene Datei.

## Aus dem Quellcode bauen

Zum Bauen brauchst du Go 1.27. `make` lädt dann selbst go1.27.2 herunter und
baut damit, sodass ein Commit auf jedem Rechner exakt dieselben Bytes ergibt.

```sh
git clone https://github.com/nning/juist
cd juist
make install      # unter FreeBSD als root: gmake install
```

`make install` baut das Paket für das System, auf dem es läuft (auf Debian
und Ubuntu das `.deb`, auf Fedora das RPM, auf FreeBSD das pkg-Paket), und
installiert es. Rufst du es später erneut auf, ersetzt der neue Build den
alten.

Soll ein Rechner juist nicht selbst bauen, baust du nur das Paket und
kopierst es hinüber:

| System | Bauen | Auf dem anderen Rechner installieren |
|---|---|---|
| Debian, Ubuntu | `make deb` | `sudo apt install ./juist_*.deb` |
| Fedora | `make rpm` | `sudo dnf install ./juist-*.rpm` |
| FreeBSD | `make pkg-freebsd` | `pkg add ./juist-*.pkg` |

Die Pakete landen in `build/deb`, `build/rpm/RPMS` und `build/freebsd`.
`make deb DEB_ARCH=arm64` baut das `.deb` für eine andere
Prozessorarchitektur, mit `armhf` und `i386` funktioniert es genauso.

## Was das Paket installiert

- Den Befehl `juist` und den Daemon `juistd`. Was welches Programm tut, steht
  unter [So funktioniert juist]({{< relref "docs/how-it-works" >}}).
- Unter Linux den Dienst `juistd`. Er startet sofort und wartet, bis du ein
  Netz anlegst oder einem beitrittst. Er läuft unter einem eigenen Benutzer,
  `juist`, und hat nur `CAP_NET_ADMIN`, auf einem
  [Relay auf Port 443]({{< relref "docs/relays" >}}) zusätzlich
  `CAP_NET_BIND_SERVICE`.
- Unter Linux zwei weitere Dienste. `juist-ingress` betreibt eine Ingress und
  wird von `juist ingress serve` gestartet. `juist-serve` ist juists eigener
  TLS-Terminator; systemd startet ihn ohne sudo, sobald `juist publish` oder
  `juist share` ihn braucht
  ([Dienste veröffentlichen]({{< relref "docs/publishing" >}})).
- Firewall-Profile für ufw und firewalld: `juist`, `juist-relay`,
  `juist-relay-443`, `juist-invite` und `juist-ingress`. Läuft ufw oder
  firewalld, lässt das Paket außerdem den Verkehr auf dem Netzwerkgerät
  `juist0` durch. Das Netz braucht ihn, um sein Log abzugleichen, und
  veröffentlichte Dienste, um erreichbar zu sein. Das geschieht nur bei der
  ersten Installation, damit ein Upgrade deine Firewall-Einstellungen nicht
  anrührt.
- Eine polkit-Regel, die juistd erlaubt, das DNS des Netzes über
  systemd-resolved einzurichten. Die Regel braucht polkit, das das Paket
  empfiehlt; Minimalinstallationen wie Fedora Cloud haben es sonst nicht.
  polkit vor 0.106, etwa unter Ubuntu 22.04, liest keine Regeln: Dort legt
  das .deb dieselbe Erlaubnis in
  `/var/lib/polkit-1/localauthority/10-vendor.d/60-juist.pkla` ab.
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

Willst du nur ein Netz verlassen und juist behalten, nimm stattdessen
`juist reset`, siehe [Geräte entfernen]({{< relref "docs/remove" >}}).

Ist das Gerät Mitglied eines Netzes, nimm es zuerst heraus, damit das Netz es
nicht weiter führt. Dazu ruft ein Admin auf seinem eigenen Gerät
`juist remove nas` auf. Danach entfernst du das Paket:

```sh
sudo apt remove juist      # Debian, Ubuntu
sudo dnf remove juist      # Fedora
pkg delete juist           # FreeBSD, als root
```

Dabei wird juistd für jedes Netz auf dem Gerät beendet, und alles, was juist
auf dem Rechner eingerichtet hat, wird rückgängig gemacht. Unter Linux sind das die
Firewall-Regel für `juist0`, eine Ingress, ein Relay auf Port 443 und die
Änderungen von `juist exit serve`.

## Was nach dem Deinstallieren bleibt

- Unter Linux bleiben die Schlüssel und das Log des Geräts in
  `/var/lib/juist`, ebenso die Systembenutzer `juist`, `juist-ingress` und
  `juist-serve`. Auf Debian und Ubuntu löscht `sudo apt purge juist` das
  Verzeichnis `/var/lib/juist` nur, wenn es leer ist. Andernfalls meldet es:
  `juist: kept /var/lib/juist, which still holds this device's keys and log`.
- Auch `/var/lib/juist-serve` bleibt (unter FreeBSD `/var/db/juist-serve`).
  Darin liegt das ACME-Konto des TLS-Terminators, auf das die CAA-Einträge
  deiner veröffentlichten Namen verweisen können. Das Entfernen meldet das:
  `juist: kept /var/lib/juist-serve, the terminator's ACME account, which CAA records may name`.
- Unter FreeBSD gibt das Entfernen eine einzige Zeile aus, die mit
  `juist: kept` beginnt und alles aufzählt, was bleibt.
- Deine Admin-Schlüssel in `~/.config/juist` gehören nicht zum Paket und
  bleiben beim Entfernen unberührt.

## Fehlersuche

- `make install` meldet
  `make install knows apt (Debian, Ubuntu), dnf (Fedora) and pkg (FreeBSD); use make deb, rpm or pkg-freebsd`:
  Dieses System nutzt keinen der drei Paketmanager. Bau das Paket für eines
  der unterstützten Systeme und installiere es dort.
- `juist status` meldet `juistd not running`: Starte ihn mit
  `sudo systemctl enable --now juistd`, unter FreeBSD mit `service juistd start`.
- Unter Linux zeigt `journalctl -u juistd` das Log des Daemons.

---
title: Installation
linkTitle: Installation
description: Das fertige juist-Paket auf Debian, Ubuntu, Fedora oder FreeBSD installieren, den Download prüfen oder das Paket aus dem Quellcode bauen.
lead: juist installierst du als Paket deines Systems, und zwar auf jedem Gerät, das in ein Netz soll. Jedes Release bringt fertige Pakete mit, dazu eine signierte Liste ihrer Prüfsummen.
---

## Unterstützte Systeme

juist läuft unter Linux und FreeBSD. Für Debian und Ubuntu gibt es ein
`.deb`, für Fedora ein RPM und für FreeBSD 15 ein pkg-Paket. Jedes
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
{{< step on="einem Gerät mit FreeBSD 15" >}}
Installiere das Paket als root mit pkg und starte dann den Daemon:

```sh
pkg add https://github.com/nning/juist/releases/latest/download/juist-freebsd15-amd64.pkg
sysrc juistd_enable=YES && service juistd start
```

Auf arm64 nimmst du `juist-freebsd15-aarch64.pkg`. Unter Linux startet das
Paket den Daemon von selbst, unter FreeBSD startest du ihn einmal wie oben
gezeigt.

Unter FreeBSD lässt juistd pf mit eigenen Regeln laufen, die die Adressen des
Geräts im Netz dem Tunnel vorbehalten: Das LAN erreicht sie nicht. Lädt der
Host eigene pf-Regeln, muss `/etc/pf.conf` die Anker von juist aufrufen,
`nat-anchor "juist/*"`, `rdr-anchor "juist/*"` und `anchor "juist/*"`, vor
jeder Regel, die mit `quick` durchlässt; sonst warnt `juist health`.
{{< /step >}}

Installierst du später ein neueres Release, ersetzt es das alte, und der
Zustand des Geräts bleibt erhalten. Einzelheiten stehen unter
[juist aktualisieren]({{< relref "docs/updating" >}}).

## Den Download prüfen {#verifying-a-download}

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

Zum Bauen brauchst du Go 1.21 oder neuer und `make`. `make` lässt Go selbst
go1.27.3 herunterladen und baut damit, sodass ein Commit auf jedem Rechner
exakt dieselben Bytes ergibt.

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

## Im Container

Eine App im Container kann ein eigenes Gerät sein, mit eigenen Adressen und
einem eigenen Platz in den [Zugriffsregeln]({{< relref "docs/access" >}}):
juistd läuft in einem zweiten Container, der sich den Netz-Namespace mit der
App teilt, und legt dort `juist0` an. Was die App zur Adresse eines Mitglieds
öffnet, geht durch den Tunnel. Das Image baust du mit `make image` im
Quellbaum und lädst es mit `docker load`.

{{< step on="dem Gerät eines Admins" >}}
```sh
juist invite app
```
{{< /step >}}

{{< step on="dem Container-Host" >}}
In einer `compose.yaml` hält ein eigener Dienst, `netns`, den Namespace,
damit juist und die App ihn behalten, wenn einer von beiden neu startet;
`JUIST_JOIN` nimmt den Einladungslink:

```yaml
services:
  netns:
    image: registry.k8s.io/pause:3.10
    restart: unless-stopped
  juist:
    image: juist:VERSION
    network_mode: service:netns
    user: "0:0"
    cap_drop: [ALL]
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun]
    environment:
      JUIST_JOIN: "juist:…"
    volumes:
      - type: volume
        source: juist
        target: /var/lib/juist
        volume:
          nocopy: true
    restart: unless-stopped
  app:
    image: …   # die App
    network_mode: service:netns
    depends_on: [juist]
    restart: unless-stopped
volumes:
  juist: {}
```

```sh
docker compose up -d
```

Wie der Beitritt lief, zeigt `docker compose logs juist`, die Adressen des
Geräts `docker compose exec juist juist status`. Nach dem Beitritt ist der
Link verbraucht und `JUIST_JOIN` wird ignoriert.
{{< /step >}}

- juistd braucht `CAP_NET_ADMIN` und `/dev/net/tun`, kein `privileged`.
  Docker gibt eine Capability nur root, also läuft juistd dort als root, ohne
  jede andere Capability, auf einem Volume, das root gehört: `nocopy`
  verhindert, dass es dem Benutzer des Images gehört. Podman gibt sie dem
  Benutzer des Images; dort kommt die `compose.podman.yaml` des Beispiels
  dazu.
- Die Namen des Netzes werden in den Containern nicht aufgelöst, da dort kein
  systemd-resolved läuft, und `juist health` sagt das. Nimm die Adressen, die
  `juist devices` auflistet, oder trag Namen mit `extra_hosts` an `netns`
  in die `/etc/hosts` des Namespace ein, mit der IPv6-Adresse, die beim
  Umnummerieren gleich bleibt.
- Startet `netns` neu, startet `docker compose restart netns` juist und die
  App mit ihm neu; sonst bleiben sie in seinem alten Namespace.
- Statt `netns` kann ein Tailscale-Container im Userspace-Modus den
  Namespace halten, mit `network_mode: service:tailscale`; die beiden kommen
  sich nicht in die Quere.

Dasselbe mit Kommentaren, einer `.env` und Podmans Ergänzung:
[examples/sidecar](https://github.com/nning/juist/tree/main/examples/sidecar)
im Repository.

## Was das Paket installiert

- Den Befehl `juist` und den Daemon `juistd`. Was welches Programm tut, steht
  unter [So funktioniert juist]({{< relref "docs/how-it-works" >}}).
- Unter Linux den Dienst `juistd`. Er startet sofort und wartet, bis du ein
  Netz anlegst oder einem beitrittst. Er läuft als Benutzer `juist`, nur mit
  `CAP_NET_ADMIN`, auf einem [Relay auf Port 443]({{< relref "docs/relays" >}})
  zusätzlich mit `CAP_NET_BIND_SERVICE`. Weitere Netze laufen als die
  Benutzer `juist1` bis `juist9`, die das Paket ebenfalls anlegt.
- Unter Linux zwei weitere Dienste: `juist-ingress` für einen
  [Ingress]({{< relref "docs/publishing" >}}), gestartet von
  `juist ingress serve`, und `juist-serve`, den TLS-Terminator von juist, den
  systemd startet, wenn `juist publish` oder `juist share` ihn braucht.
- Firewall-Profile für ufw und firewalld: `juist`, `juist-relay`,
  `juist-relay-443`, `juist-invite` und `juist-ingress`. Läuft ufw oder
  firewalld, lässt das Paket außerdem Verkehr auf `juist0` durch, den der
  Log-Abgleich und veröffentlichte Dienste brauchen. Das geschieht nur bei der
  ersten Installation, ein Upgrade lässt deine Firewall in Ruhe.
- Eine polkit-Regel, die juistd erlaubt, das DNS des Netzes über
  systemd-resolved einzurichten. Sie braucht polkit, das das Paket empfiehlt;
  Minimalinstallationen wie Fedora Cloud haben es nicht. Unter Ubuntu 22.04,
  dessen polkit keine Regeln liest, legt das .deb dieselbe Erlaubnis in
  `/var/lib/polkit-1/localauthority/10-vendor.d/60-juist.pkla` ab.
- Shell-Vervollständigung für bash, zsh und fish sowie die Man-Pages
  `juist(1)` und `juistd(8)`.

Ob der Daemon läuft, siehst du so:

```console {device="nas"}
$ juist status
nas · no network
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
Firewall-Regel für `juist0`, ein Ingress, ein Relay auf Port 443 und die
Änderungen von `juist exit serve`.

## Was nach dem Deinstallieren bleibt

- Unter Linux bleiben die Schlüssel und das Log des Geräts in
  `/var/lib/juist`, die eines weiteren Netzes in `/var/lib/juist1` usw.,
  ebenso die Systembenutzer `juist`, `juist1` bis `juist9`, `juist-ingress`
  und `juist-serve`. Auf Debian und Ubuntu löscht `sudo apt purge juist` jedes
  dieser Verzeichnisse nur, wenn es leer ist. Andernfalls meldet es:
  `juist: kept /var/lib/juist, which still holds this device's keys and log`.
- Auch `/var/lib/juist-serve` bleibt (unter FreeBSD `/var/db/juist-serve`).
  Darin liegt das ACME-Konto des TLS-Terminators, auf das die CAA-Einträge
  deiner veröffentlichten Namen verweisen können. `sudo apt purge juist`
  unter Debian und Ubuntu und `sudo dnf remove juist` unter Fedora melden
  das:
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
- `juist status` meldet `juist0 · not running`, unter FreeBSD vor dem
  Aktivieren `juistd not running`: Starte den Daemon mit
  `sudo systemctl enable --now juistd`, unter FreeBSD als root mit
  `sysrc juistd_enable=YES && service juistd start`.
- Unter Linux zeigt `journalctl -u juistd` das Log des Daemons; unter FreeBSD
  steht es in `/var/log/juistd.log`.

---
title: Namen
linkTitle: Namen
description: Geräte über ihren Namen statt über ihre Adresse erreichen und öffentliche Namen durch den Tunnel zu einem Mitglied leiten.
lead: Jedes Gerät in deinem Netz hat einen Namen, etwa nas.home.juist oder einfach nas. Du kannst auch einen öffentlichen Namen wie mail.example.org auf ein Gerät verweisen lassen, damit Mitglieder es durch den Tunnel erreichen.
---

## So funktionieren Namen

Jedes Gerät im Netz ist ein **Mitglied**, und jedes Mitglied hat einen Namen.
Daraus macht juist einen DNS-Namen der Form `DEVICE.NETWORK.juist`. Im Netz
`home` heißt das Gerät `nas` also `nas.home.juist`, und einfach `nas`
funktioniert auch. Dafür musst du nichts einschalten.

Außerdem kannst du einen **öffentlichen Namen** auf ein Mitglied verweisen
lassen. Angenommen, auf deinem NAS läuft ein Mailserver, den das Internet als
`mail.example.org` kennt. Auf Geräten, die öffentliche Namen eingeschaltet
haben, führt `mail.example.org` dann durch den Tunnel zum NAS statt über das
Internet. Weil der Name derselbe bleibt, passt auch das Zertifikat des
Servers weiterhin. Für den Rest des Internets ändert sich nichts.

Beides funktioniert unter Linux und FreeBSD. Wo systemd-resolved läuft,
schickt es diese Namen an juistd. Anderswo beantwortet
juistd das DNS des Geräts selbst, solange es läuft: die Namen des Netzes,
und jeden anderen Namen über die Resolver, die das Gerät vorher hatte. Unter
Linux lässt der Dienst des Pakets `/etc/resolv.conf` auf eine Datei zeigen,
die juistd schreibt, und stellt sie zurück, wenn juistd endet; unter FreeBSD
gibt juistd seinen Resolver an resolvconf. Eine `/etc/resolv.conf`, die
Tailscale geschrieben hat, bleibt die von Tailscale, und die Namen des Netzes
werden auf diesem Gerät nicht aufgelöst.

## Ein Gerät über seinen Namen erreichen

```sh {device="laptop"}
ssh nas.home.juist
ssh nas
```

Beide Befehle führen zum NAS, und zwar zu seinen Adressen im Netz.

## Einen öffentlichen Namen auf ein Gerät verweisen lassen

{{< step on="dem Gerät eines Admins" >}}
Lass den Namen auf das Gerät verweisen:

```sh
juist names add nas mail.example.org
```

Die Ausgabe lautet `nas: names mail.example.org`. Das ist eine Änderung am
Netz und muss deshalb wie jede andere von den Admins bestätigt werden
([Änderungen bestätigen]({{< relref "docs/network-changes" >}})).
{{< /step >}}

{{< step on="jedem Gerät, das ihn nutzen soll" >}}
Schalte öffentliche Namen auf diesem Gerät ein:

```sh
juist names on
```

Die Ausgabe lautet `public names on: mail.example.org at nas`.
{{< /step >}}

`juist names` listet die Namen des Netzes auf, auch die öffentlichen, und
zeigt, wie dieses Gerät sie jeweils auflöst. Nach `juist names off` löst das Gerät sie wieder
öffentlich auf, und `juist names remove nas mail.example.org` nimmt dem Gerät
den Namen wieder weg.

## Warum jedes Gerät sie selbst einschaltet

Ein öffentlicher Name im Netz setzt sich über das hinweg, was das Internet
über diesen Namen sagt. Die Admins, die eine solche Änderung bestätigen,
könnten also jeden beliebigen öffentlichen Namen auf ein Mitglied ihrer Wahl
umleiten. Eine Verbindung, die ein Zertifikat prüft, würde dann scheitern,
weil das Mitglied kein Zertifikat für diesen Namen hat. Unverschlüsseltes
HTTP, Mail ohne Zertifikatsprüfung und viele interne Werkzeuge würden es aber
nicht bemerken.

Deshalb entscheidet jedes Gerät selbst. Auf einem Gerät, auf dem niemand
`juist names on` ausgeführt hat, werden öffentliche Namen aufgelöst wie ohne
juist. Die Namen der Mitglieder, etwa `nas.home.juist`, betreffen nichts
außerhalb des Netzes und brauchen keine Zustimmung.

Die Ausnahme ist die eigene Domain des Netzes zum
[Veröffentlichen]({{< relref "docs/publishing" >}}). Sobald die Admins sie
setzen, löst jedes Mitglied diese Domain über juistd auf, ob öffentliche Namen
eingeschaltet sind oder nicht, und DNSSEC ist für sie auf Mitgliedern aus. Ein
dort auf Port 443 veröffentlichter Name führt direkt zu seinem Gerät, jeder
andere Name der Domain wird aufgelöst wie bisher. `juist network domain` warnt
davor, und die Admins sehen es, wenn sie die Änderung bestätigen. Setze nur
eine Domain, die dir gehört: Das kann juist nicht prüfen.

## Das DNS dieses Geräts in Ruhe lassen

```sh
sudo juist set --dns=false
```

Die Ausgabe lautet `dns off`. juistd lässt das DNS dieses Geräts dann, wie es
war: keine Namen des Netzes und kein DNS über einen Exit-Node, das dann an
die eigenen Resolver des Geräts außerhalb des Tunnels geht. Die Zeile `Names`
in `juist status` endet dann auf `(DNS off)`, und `juist health` sagt, was das
bedeutet. `sudo juist set --dns` schaltet es wieder ein. Beides wirkt ohne
Neustart.

## Hinweise

- Ein öffentlicher Name hat mindestens zwei Labels, etwa `example.org`, und liegt nicht unter `.juist`.
- Jeder öffentliche Name verweist auf genau ein Gerät. Ein Gerät kann bis zu 32 solcher Namen haben.
- Ist das Gerät eines öffentlichen Namens nicht erreichbar oder ist der Stand dieses Geräts veraltet, wird der Name wieder öffentlich aufgelöst. Die Verbindung geht dann an die öffentliche Adresse, wie ohne juist.
- Ein Gerät, dessen Name kein gültiges DNS-Label ist, bekommt keinen Namen unter `.juist`.
- Unter [Zugriffsregeln]({{< relref "docs/access" >}}) kennt ein Gerät nur die Namen der Mitglieder, zu denen es einen Tunnel hat. Die öffentlichen Namen der anderen löst es öffentlich auf.
- In `juist devices` zeigt ein Gerät, auf das öffentliche Namen verweisen, `names` in der Spalte `ROLES`. `juist names` listet die Namen auf.

## Fehlersuche

Die Zeile `Names` in [`juist status`]({{< relref "docs/status" >}}) nennt die
eigenen Namen dieses Geräts, etwa `nas.home.juist, mail.example.org`, und endet
auf `(DNS off)`, wo DNS aus ist. `juist names` listet alle Namen des Netzes,
auch seine Domains, und wie dieses Gerät jeden auflöst. Werden sie nicht
aufgelöst oder ist ein öffentlicher Name aus, sagt
[`juist health`]({{< relref "docs/status" >}}), warum:

| `juist health` zeigt | Bedeutung |
|---|---|
| `1 public name, off on this device` | es gibt einen öffentlichen Namen, aber dieses Gerät hat öffentliche Namen nicht eingeschaltet |
| `mail.example.org resolved publicly: nas is not reachable` | der öffentliche Name führt vorerst zu seiner öffentlichen Adresse |
| `warning: home.juist not resolved here: systemd-resolved refused juistd` | systemd-resolved hat juistd nicht erlaubt, das DNS einzurichten |
| `warning: home.juist not resolved here: systemd-resolved refused juistd: polkit is not installed` | dasselbe, auf einem Host ohne polkit, das die Regel des Pakets ausführt |
| `warning: home.juist not resolved here: /etc/resolv.conf lists every link's servers, systemd-resolved's uplink mode, not its stub` | Programme auf diesem Gerät umgehen systemd-resolved |
| `warning: home.juist not resolved here: systemd-resolved does not run on this host` | juistd läuft ohne den Dienst des Pakets, der ihm `/etc/resolv.conf` übergibt |
| `warning: home.juist not resolved here: tailscaled writes /etc/resolv.conf` | Tailscale beantwortet das DNS dieses Geräts; `sudo tailscale set --accept-dns=false` und `sudo systemctl restart juistd` übergeben es juistd, ohne die Namen des Tailnets |
| `warning: home.juist not resolved here: /etc/resolv.conf is no longer juistd's` | ein anderes Programm, etwa ein DHCP-Client, hat `/etc/resolv.conf` geschrieben; `sudo systemctl restart juistd` übergibt sie wieder |
| `warning: home.juist not resolved here: /etc/resolv.conf asks …, not juistd` | unter FreeBSD lässt resolvconf eine `resolv.conf` in Ruhe, die es nicht selbst geschrieben hat |

Hat systemd-resolved juistd abgewiesen, ergänzt `juist health`:

```console
hint: the package's polkit rule allows juistd that: /usr/share/polkit-1/rules.d/60-juist.rules
```

Installiere juist als Paket (siehe
[Installation]({{< relref "docs/install" >}})), das diese Regel mitbringt.
Fehlt polkit, etwa nach `dpkg -i`, das die von juist empfohlenen Pakete
auslässt, installiert der Hinweis es:

```console
hint: sudo apt install polkitd, or sudo dnf install polkit
```

juistd versucht es binnen einer Minute erneut, ohne Neustart. Im Uplink-Modus nennt der Hinweis
den Befehl, mit dem `/etc/resolv.conf` auf den Stub verweist:

```sh
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```

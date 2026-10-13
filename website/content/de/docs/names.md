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

Beides funktioniert unter Linux auf Geräten mit systemd-resolved. Der
Resolver von FreeBSD kann diese Namen nicht weiterleiten. Dort funktionieren
sie deshalb nicht, und `juist status` weist darauf hin.

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

`juist names` listet die öffentlichen Namen auf und zeigt, wie dieses Gerät
sie jeweils auflöst. Nach `juist names off` löst das Gerät sie wieder
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

## Hinweise

- Ein öffentlicher Name hat mindestens zwei Labels, etwa `example.org`, und liegt nicht unter `.juist`.
- Jeder öffentliche Name verweist auf genau ein Gerät. Ein Gerät kann bis zu 32 solcher Namen haben.
- Ist das Gerät eines öffentlichen Namens nicht erreichbar oder ist der Stand dieses Geräts veraltet, wird der Name wieder öffentlich aufgelöst. Die Verbindung geht dann an die öffentliche Adresse, wie ohne juist.
- Ein Gerät, dessen Name kein gültiges DNS-Label ist, bekommt keinen Namen unter `.juist`.
- Unter [Zugriffsregeln]({{< relref "docs/access" >}}) kennt ein Gerät nur die Namen der Mitglieder, zu denen es einen Tunnel hat. Die öffentlichen Namen der anderen löst es öffentlich auf.
- In `juist devices` zeigt ein Gerät, auf das öffentliche Namen verweisen, `names` in der Spalte `ROLES`. `juist names` listet die Namen auf.

## Fehlersuche

Die Zeile `Names` in [`juist status`]({{< relref "docs/status" >}}) zeigt,
wie dieses Gerät die Namen des Netzes auflöst:

| `Names` zeigt | Bedeutung |
|---|---|
| `home.juist` | die Namen der Mitglieder funktionieren |
| `home.juist; mail.example.org at nas` | die Namen der Mitglieder und die öffentlichen Namen funktionieren |
| `home.juist; 1 public name, off on this device` | es gibt einen öffentlichen Namen, aber dieses Gerät hat öffentliche Namen nicht eingeschaltet |
| `home.juist not resolved: systemd-resolved refused juistd` | systemd-resolved hat juistd nicht erlaubt, das DNS einzurichten |
| `home.juist not resolved: systemd-resolved refused juistd: polkit is not installed` | dasselbe, auf einem Host ohne polkit, das die Regel des Pakets ausführt |
| `home.juist not resolved: /etc/resolv.conf lists every link's servers, systemd-resolved's uplink mode, not its stub` | Programme auf diesem Gerät umgehen systemd-resolved |

Hat systemd-resolved juistd abgewiesen, ergänzt `juist status`:

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

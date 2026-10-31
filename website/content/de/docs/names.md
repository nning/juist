---
title: Namen
linkTitle: Namen
description: Geräte über ihren Namen statt über ihre Adresse erreichen und öffentliche Namen durch den Tunnel zu einem Mitglied leiten.
lead: Jedes Gerät in deinem Netz hat einen Namen, etwa nas.home.juist oder einfach nas. Du kannst auch einen öffentlichen Namen wie mail.example.org auf ein Gerät verweisen lassen, damit Mitglieder es durch den Tunnel erreichen.
---

## So funktionieren Namen

Jedes Mitglied hat einen DNS-Namen: `DEVICE.NETWORK.juist`. Im Netz `home`
heißt das Gerät `nas` also `nas.home.juist`, und einfach `nas` funktioniert
auch. Dafür musst du nichts einschalten.

Außerdem kannst du einen **öffentlichen Namen** auf ein Mitglied verweisen
lassen. Angenommen, auf deinem NAS läuft ein Mailserver, bekannt als
`mail.example.org`. Auf Geräten, die öffentliche Namen eingeschaltet haben,
führt der Name dann durch den Tunnel zum NAS. Das Zertifikat passt weiter, und
für den Rest des Internets ändert sich nichts.

Beides funktioniert unter Linux und FreeBSD, wo juist das DNS des Geräts
selbst einrichtet ([wie](#resolver)). Die
[Android-App]({{< relref "docs/android" >}}#names) löst die Namen der
Mitglieder und die unter der Domain des Netzes veröffentlichten auf, keine
öffentlichen Namen.

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

Die Ausgabe lautet `nas: names mail.example.org`. Wie jede Änderung müssen
die Admins sie bestätigen
([Änderungen bestätigen]({{< relref "docs/network-changes" >}})).
{{< /step >}}

{{< step on="jedem Gerät, das ihn nutzen soll" >}}
Schalte öffentliche Namen auf diesem Gerät ein:

```sh
juist names on
```

Die Ausgabe lautet `public names on: mail.example.org at nas`.
{{< /step >}}

`juist names` listet die Namen des Netzes auf und wie dieses Gerät jeden
auflöst. Nach `juist names off` löst das Gerät sie wieder öffentlich auf.
`juist names remove nas mail.example.org` nimmt dem Gerät den Namen.

## Warum jedes Gerät sie selbst einschaltet

Ein öffentlicher Name im Netz setzt sich über das hinweg, was das Internet
sagt. Die Admins könnten jeden öffentlichen Namen auf ein Mitglied umleiten.
Eine Verbindung, die das Zertifikat prüft, würde scheitern, aber
unverschlüsseltes HTTP, Mail ohne Zertifikatsprüfung und viele interne
Werkzeuge würden es nicht bemerken.

Deshalb entscheidet jedes Gerät selbst. Ohne `juist names on` löst ein Gerät
öffentliche Namen auf wie ohne juist. Die Namen der Mitglieder, etwa
`nas.home.juist`, betreffen nichts außerhalb des Netzes und brauchen keine
Zustimmung.

Die Ausnahme ist die Domain des Netzes zum
[Veröffentlichen]({{< relref "docs/publishing" >}}). Sobald die Admins sie
setzen, löst jedes Mitglied sie über juistd auf, mit ausgeschaltetem DNSSEC.
Ein dort auf Port 443 veröffentlichter Name führt direkt zu seinem Gerät,
andere Namen der Domain werden aufgelöst wie bisher. Setze nur eine Domain,
die dir gehört: Das kann juist nicht prüfen.

## Das DNS dieses Geräts in Ruhe lassen

```sh
sudo juist set --dns=false
```

Die Ausgabe lautet `dns off`. juistd lässt das DNS dieses Geräts dann in
Ruhe: keine Namen des Netzes und kein DNS über einen Exit-Node. Die Zeile
`Names` in `juist status` endet auf `(DNS off)`. `sudo juist set --dns`
schaltet es wieder ein, ohne Neustart.

## Gut zu wissen

- Ein öffentlicher Name hat mindestens zwei Labels, etwa `example.org`, und
  liegt nicht unter `.juist`, `.local`, `.localhost`, `.arpa`, `.invalid`
  oder `.onion`.
- Jeder öffentliche Name verweist auf ein Gerät. Ein Gerät kann bis zu 32
  haben.
- Ist sein Gerät nicht erreichbar oder der Stand dieses Geräts veraltet, wird
  ein öffentlicher Name wieder öffentlich aufgelöst.
- Ein Gerät, dessen Name kein gültiges DNS-Label ist, hat keinen Namen unter
  `.juist`.
- Unter [Zugriffsregeln]({{< relref "docs/access" >}}) kennt ein Gerät nur
  die Namen der Mitglieder, zu denen es einen Tunnel hat.
- Beantwortet juistd das ganze DNS eines Geräts, beantwortet es auch
  Rückwärtsabfragen der Adressen des Netzes.

## So löst das Gerät Namen auf {#resolver}

- Mit systemd-resolved schickt dieses die Anfragen nach den Namen des Netzes
  an juistd. Namen, die juistd weitergibt, gehen dorthin, wohin
  systemd-resolved sie schicken würde. juistd weist Namen ab, die
  systemd-resolved über DNS over TLS fragen würde, statt sie unverschlüsselt
  zu schicken, und Namen, die nur der Resolver von Tailscale beantworten
  würde. `juist health` sagt das.
- Unter Linux ohne systemd-resolved beantwortet juistd das gesamte DNS des
  Geräts, solange es läuft, andere Namen über die Resolver, die das Gerät
  vorher nutzte. Das Paket lässt `/etc/resolv.conf` auf die Datei von juistd
  zeigen und stellt sie zurück, wenn juistd endet.
- Unter FreeBSD übergibt juistd seinen Resolver an resolvconf.
- Unter Android siehe [die Namen der App]({{< relref "docs/android" >}}#names).
- Hat Tailscale `/etc/resolv.conf` geschrieben, lässt juist sie in Ruhe, und
  die Namen des Netzes werden auf diesem Gerät nicht aufgelöst.

## Fehlersuche

`juist names` listet alle Namen des Netzes auf und wie dieses Gerät jeden
auflöst. Werden Namen nicht aufgelöst oder ist ein öffentlicher Name aus,
sagt [`juist health`]({{< relref "docs/status" >}}), warum:

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
| `warning: names juistd forwards are refused: the host asks tailscaled alone, whose answers members cannot reach` | ein Exit-Node weist Mitgliedern die Namen ab, die der Host allein an Tailscale schickt; `sudo tailscale set --accept-dns=false` auf ihm überlässt die Namen des Tailnets seinen anderen Resolvern |
| `warning: names juistd forwards are refused: systemd-resolved asks over DNS over TLS, which juistd does not speak` | juistd weist diesem Gerät Namen ab, die systemd-resolved über TLS fragen würde, statt sie unverschlüsselt zu schicken; `juist exit use DEVICE` schickt sie durch den Tunnel |
| `warning: names juistd forwards are refused: systemd-resolved knows no DNS server` | systemd-resolved hat keinen Server zu fragen; `resolvectl status` zeigt die Server, die es kennt |
| `warning: names the host's DNS routing sends elsewhere are refused, as it cannot be read: …` | juistd kann systemd-resolved nicht fragen, wohin ein Name geht, und weist solche Namen ab, bis es das kann; `systemctl status systemd-resolved` zeigt, wie es steht |

Hat systemd-resolved juistd abgewiesen, ergänzt `juist health`:

```console
hint: the package's polkit rule allows juistd that: /usr/share/polkit-1/rules.d/60-juist.rules
```

Installiere juist als Paket ([Installation]({{< relref "docs/install" >}})),
das diese Regel mitbringt. Fehlt polkit, etwa nach `dpkg -i`, installiert der
Hinweis es:

```console
hint: sudo apt install polkitd, or sudo dnf install polkit
```

juistd versucht es binnen einer Minute erneut, ohne Neustart. Im
Uplink-Modus lässt der Hinweis `/etc/resolv.conf` auf den Stub zeigen:

```sh
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```

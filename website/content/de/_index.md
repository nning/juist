---
title: juist
description: Ein Peer-to-Peer-Mesh-VPN ohne Koordinationsserver. WireGuard überträgt den Verkehr, und wer zum Netz gehört, steht in einem Log, das deine Admins signieren.
headline: Ein Mesh-VPN ohne Koordinationsserver
lead: WireGuard überträgt den Verkehr. Wer zum Netz gehört, steht in einem Log, das deine Admins signieren, und jedes Gerät prüft dieses Log selbst.
links:
  - {label: Funktionen, anchor: features}
  - {label: Trade-offs, anchor: trade-offs}
  - {page: docs/architecture}
  - {page: docs/compare}
  - {page: docs}
---

{{< rules >}}
Kein Server in der Mitte
: Geräte finden einander im LAN, über andere Mitglieder oder über den öffentlichen BitTorrent-DHT. Sie kommen durch NAT, und wo das nicht klappt, springt ein Relay ein, das auf einem deiner eigenen Geräte läuft.

Änderungen brauchen deine Admins
: Um ein Gerät aufzunehmen oder zu entfernen, braucht es ein Quorum von Admins, jeder mit einem Schlüssel auf seinen eigenen Geräten. Die Schlüssel bleiben im Keystore, der Daemon bekommt sie nie.

Fail-closed
: Hat sich 48 Stunden lang kein Voucher für ein Gerät verbürgt, behält es nur noch Tunnel zu Vouchern. So hält es keine Verbindung zu einem Gerät, das längst entfernt wurde.
{{< /rules >}}

## Das erste Netz

Auf dem ersten Gerät legst du mit `juist create` ein Netz an. `juist invite`
gibt dann einen Code fürs LAN und einen Link für alle anderen Fälle aus, und
das neue Gerät tritt mit einem von beiden bei. Anschließend zeigen beide
Geräte vier Wörter. Erst wenn du sie verglichen hast, wird das Gerät
aufgenommen.

```console {device="laptop"}
$ juist create home
created network "home"
$ juist invite
invite to "home", expires in 1h; on the new device:

  juist join 42-drumbeat-tolerance-glucose  # same LAN

  juist join 'juist:Kx7q…@192.168.1.20:41642'

nas wants to join; compare with the words it shows:
  atlas-amulet-banjo-asteroid
same? [y/N] y
admitting nas (nid:fcRW83T_…)
admitted nas at 198.18.36.2
nas joined
```

## Funktionen {#features}

Für Netze mit 25 bis 100 Geräten und wenigen Admins.

{{< features >}}

## Dienste veröffentlichen {#publishing}

Dienste auf deinen Mitgliedern, etwa auf dem NAS zu Hause, kannst du unter
einem Namen im Internet erreichbar machen. Ein Gerät mit öffentlicher Adresse,
die Ingress, liest den Namen, den der Client anfragt, und reicht die
Verbindung durch den Tunnel weiter. TLS endet erst beim Mitglied, die Ingress
bekommt den Inhalt also nie zu sehen.

{{< flow publish >}}

Wie du das einrichtest, steht im [Handbuch]({{< relref "docs/publishing" >}}).

## Trade-offs {#trade-offs}

Ohne Server in der Mitte ist manches schwächer als mit einem. Zu jedem Punkt
steht hier, was passieren kann, warum juist das in Kauf nimmt und was du
dagegen tun kannst. Die vollständige Liste steht in [02-threat-model.md](https://github.com/nning/juist/blob/main/docs/02-threat-model.md).

### Mitgliedschaft

{{< trade title="Entfernen wirkt nicht überall sofort" knob="juist admins vouchers M" >}}
Was passiert
: Ist ein Gerät vom Netz abgeschnitten, hält es Tunnel zu einem entfernten Gerät, bis es davon erfährt.

Warum juist das hinnimmt
: Es gibt keinen Server, den jedes Gerät fragen könnte. Die Frische setzt dem eine Grenze: Hat sich 48 Stunden lang kein Voucher für ein Gerät verbürgt, behält es nur noch Tunnel zu Vouchern.

Was du tun kannst
: M Voucher verlangen. Dann hält die Grenze auch, wenn M − 1 von ihnen lügen.
{{< /trade >}}

{{< trade title="Ein verlorenes Quorum ist endgültig" knob="mehr Admins, als das Quorum braucht" >}}
Was passiert
: Bleiben weniger als k Admin-Schlüssel übrig, lässt sich keine Änderung mehr signieren, nie wieder.

Warum juist das hinnimmt
: Jeder Weg am Quorum vorbei stünde auch Angreifern offen.

Was du tun kannst
: Mehr Admins einsetzen, als das Quorum braucht, jeden mit eigenen Geräten.
{{< /trade >}}

### Erreichbarkeit

{{< trade title="Symmetrisches NAT überall braucht ein Relay" knob="juist grant vps relay" >}}
Was passiert
: Stehen alle Geräte hinter symmetrischem NAT, kommt kein direkter Tunnel zustande.

Warum juist das hinnimmt
: Das Relay ist eines deiner eigenen Mitglieder und sieht nur verschlüsselten WireGuard-Verkehr.

Was du tun kannst
: Einem Gerät mit öffentlicher Adresse die Rolle `relay` geben.
{{< /trade >}}

{{< trade title="Öffentliche Helfer sehen Adressen" knob="--no-dht --no-stun" >}}
Was passiert
: Der öffentliche BitTorrent-DHT und die STUN-Server sehen die Adressen der Geräte, die sie nutzen.

Warum juist das hinnimmt
: juist vertraut nichts, was sie liefern. Ein kompromittierter Helfer kann Verbindungen verzögern, aber nicht ändern, wer zum Netz gehört.

Was du tun kannst
: juistd ohne sie betreiben und den Geräten selbst Adressen mitgeben, unter denen sie sich erreichen.
{{< /trade >}}

### Kryptographie

{{< trade title="Tunnelverkehr ist nicht quantensicher" knob="keine Einstellung" >}}
Was passiert
: Ein künftiger Quantencomputer könnte mitgeschnittenen WireGuard-Verkehr entschlüsseln.

Warum juist das hinnimmt
: WireGuard hat keinen Schlüsselaustausch, der gegen Quantencomputer sicher ist. Die Gruppengeheimnisse sind dagegen hybrid geschützt, mit X25519 und ML-KEM-768.

Was du tun kannst
: Nichts. Für Verkehr, der Jahrzehnte geheim bleiben muss, solltest du dich nicht auf juist verlassen.
{{< /trade >}}

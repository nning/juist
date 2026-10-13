---
title: Architektur
linkTitle: Architektur
description: Wie juist aufgebaut ist, Schicht für Schicht, inwiefern es Zero Trust umsetzt und was es von WireGuard und Tailscale übernimmt.
lead: juist ist ein Mesh-VPN ohne Koordinationsserver. Hier erfährst du, wie es aufgebaut ist, was es von WireGuard und Tailscale übernimmt und inwiefern es Zero Trust umsetzt.
---

## Kurz gesagt {#overview}

Die meisten Mesh-VPNs haben einen Koordinationsserver. Er kennt alle Geräte
und ihre Schlüssel und teilt jedem Gerät mit, mit wem es sprechen darf. Über
ihn nimmt ein Admin Geräte auf oder entfernt sie. Wer den Server betreibt oder
in ihn einbricht, bestimmt also, wer zum Netz gehört.

juist kommt ohne einen solchen Server aus. Seine Aufgabe übernimmt das
[Mitgliederlog]({{< relref "docs/how-it-works" >}}#the-membership-log): Deine
Admins signieren es, und jedes Gerät prüft es selbst. Für alles andere
(Geräte finden, durch NAT kommen, Verkehr übertragen) kann juist Wege und
Helfer nutzen, denen es nicht vertraut.

Die Begriffe auf dieser Seite erklärt
[So funktioniert juist]({{< relref "docs/how-it-works" >}}). Worin sich juist
von anderen Mesh-VPNs unterscheidet, steht unter
[juist im Vergleich]({{< relref "docs/compare" >}}).

## Zero Trust {#zero-trust}

Zero Trust ist ein Sicherheitsmodell, in dem nichts allein deshalb als
vertrauenswürdig gilt, weil es an einer bestimmten Stelle im Netz steht. Jeder
Zugriff wird zuerst authentifiziert, ob er aus dem LAN kommt oder von
außerhalb. Das NIST beschreibt das Modell in
[SP 800-207](https://doi.org/10.6028/NIST.SP.800-207), ein bekanntes Beispiel
ist Googles
[BeyondCorp](https://research.google/pubs/beyondcorp-a-new-approach-to-enterprise-security/).

Diese Grundsätze setzt juist um:

- Adressen bedeuten nichts. Ein Paket wird nur angenommen, wenn es durch einen
  WireGuard-Tunnel kommt, und zwar von einem Schlüssel, den das Mitgliederlog
  zulässt. Ein Gerät im selben LAN kommt nicht durch, auch keines, das sich
  als Mitglied ausgibt.
- Weder Servern noch Übertragungswegen wird vertraut. Jedes Gerät prüft jede
  Änderung am Netz anhand der Signaturen der Admins, egal auf welchem Weg sie
  kam.
- Kein Schlüssel entscheidet allein. Ab einem Quorum von zwei kann ein
  gestohlener Admin-Schlüssel für sich nichts ändern, und juistd hat nie einen
  Admin-Schlüssel.
- Vertrauen ist nicht von Dauer. Ein entferntes Gerät verliert seine Tunnel,
  sobald die anderen Mitglieder davon erfahren. Bei abgeschnittenen
  Mitgliedern dauert das dank der
  [Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)
  höchstens 48 Stunden.

Hier bleibt juist hinter dem Modell zurück:

- Ohne [Zugriffsregeln]({{< relref "docs/access" >}}) erreicht ein
  aufgenommenes Gerät jeden Port jedes anderen Mitglieds. Die Regeln nennen
  Geräte, keine Benutzer. Dienste auf den Mitgliedern sollten deshalb
  weiterhin selbst prüfen, wer sich verbindet.
- juist kennt nur Geräte, keine Benutzer. Es prüft weder, wer vor einem Gerät
  sitzt, noch ob das Gerät auf dem neuesten Stand ist.

## Die Schichten {#layers}

juist besteht aus vier Schichten. Jede Schicht verlässt sich darauf, dass die
Schichten darunter Pakete zustellen. Wer zum Netz gehört, entscheiden diese
aber nie.

| Schicht | Aufgabe | Vertraut für | Gebaut aus |
|---|---|---|---|
| Vertrauen | Mitgliederlog, Quorum, Gruppengeheimnis, Frische und Einladungen | Wer zum Netz gehört | juist |
| Abgleich | Überträgt Log-Einträge und Adressen: von Mitglied zu Mitglied, im LAN und über den DHT | Nichts, jeder Eintrag ist signiert | juist, BitTorrent-DHT |
| Verbindung | Findet einen Weg zwischen zwei Geräten, durch NAT oder über ein Relay | Nichts, sie kann eine Verbindung verzögern, aber nie erlauben | Tailscale: magicsock, DERP |
| Datenebene | Verschlüsselt und authentifiziert jedes Paket zwischen zwei Geräten | Dass Verkehr geheim und unverändert bleibt | Tailscale: wireguard-go |

Die Schichten unterhalb der Vertrauensschicht können eine Verbindung verzögern
oder verhindern. Sie können aber weder ändern, wer Mitglied ist, noch Verkehr
mitlesen oder verändern. Ganz unten sorgt WireGuard dafür: juistd richtet die
WireGuard-Peers ausschließlich nach dem Mitgliederlog ein.

Aus dem Stand des Logs erzeugt juistd alles, was das Betriebssystem zu sehen
bekommt: WireGuard-Peers, Paketfilter, Routen und Namen. Bei jeder neuen
Änderung geschieht das erneut.

## WireGuard {#wireguard}

[WireGuard](https://www.wireguard.com/) ist ein VPN-Protokoll von Jason A.
Donenfeld. Er beschreibt es in seinem Paper
[WireGuard: Next Generation Kernel Network Tunnel](https://www.wireguard.com/papers/wireguard.pdf)
(NDSS 2017). Der Handshake beruht auf dem
[Noise Protocol Framework](https://noiseprotocol.org/noise.html) und
verwendet Curve25519, ChaCha20-Poly1305 und BLAKE2s. Die Einzelheiten stehen
auf der [Protokollseite](https://www.wireguard.com/protocol/).

juist nutzt dabei, was WireGuard Cryptokey-Routing nennt. Jeder Peer besteht
aus einem öffentlichen Schlüssel und den Adressen, die er verwenden darf. Ein
Paket von einem Peer wird nur angenommen, wenn die Absenderadresse zu dessen
Schlüssel gehört. Umgekehrt geht ein Paket an eine Adresse nur an den
Schlüssel, dem diese Adresse gehört. juist füllt diese Tabelle ausschließlich
aus dem Mitgliederlog. Daraus folgt:

- Ein Schlüssel, den das Log nicht zulässt, scheitert schon am Handshake.
- Kein Mitglied kann mit der Adresse eines anderen senden.
- Eine Adresse im Netz hängt an einem Schlüssel, nicht an dem, was ein Router
  oder ein Relay behauptet.

Zusätzlich verwirft juists Paketfilter jedes eingehende Paket, das er nicht
ausdrücklich annehmen soll.

juist betreibt WireGuard auf allen Plattformen im Userspace, und zwar mit
[Tailscales Fassung](https://github.com/tailscale/wireguard-go) von
[wireguard-go](https://git.zx2c4.com/wireguard-go/), weil Tailscales
NAT-Traversal (siehe unten) das voraussetzt. Unter Linux und FreeBSD wäre
WireGuard im Kernel schneller.

Jeder WireGuard-Handshake mischt einen Preshared Key ein, den ein künftiger
Quantencomputer nicht herausfinden kann. Heute mitgeschnittener Verkehr bleibt
also geheim. Zwei Geräte beginnen mit einem Schlüssel, der aus dem
[Gruppengeheimnis](#log) abgeleitet ist. Beim Log-Abgleich kapselt dann jedes
ein Geheimnis an den ML-KEM-768-Schlüssel des anderen, und sie wechseln zu
einem Schlüssel, den nur die beiden haben. Dieser Schlüssel wird mit jeder
Änderung der Mitglieder erneuert.

## Was juist von Tailscale übernimmt {#tailscale}

[Tailscale](https://tailscale.com/blog/how-tailscale-works) ist ein Mesh-VPN
auf Basis von WireGuard. Den Koordinationsserver betreibt Tailscale Inc., der
Client ist [Open Source](https://github.com/tailscale/tailscale) unter der
BSD-3-Clause-Lizenz. juist enthält Teile dieses Clients, festgelegt auf
Version 1.104.0:

- **magicsock und disco** finden einen direkten Weg zwischen zwei Geräten und
  kommen dabei durch NAT. Wie das geht, erklärt Tailscale in
  [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works).
- **DERP** leitet Verkehr weiter, wenn kein direkter Weg zustande kommt, siehe
  [DERP servers](https://tailscale.com/kb/1232/derp-servers). Bei Tailscale
  stehen DERP-Server allen Nutzern offen. Bei juist läuft DERP auf einem
  Mitglied mit der Rolle `relay` und bedient nur Mitglieder aus dem Log.
- **wgengine** verbindet WireGuard mit dem Betriebssystem, also mit
  Netzwerkgerät, Paketfilter, Routen und DNS.
- **STUN** verrät einem Gerät seine öffentliche Adresse.

Den Teil, der mit einem Koordinationsserver spricht, lässt juist weg.
Tailscales Client bekommt seine Peers und deren Schlüssel von diesem Server,
juist übergibt demselben Code stattdessen Peers, die es aus dem Mitgliederlog
erzeugt hat. Du brauchst kein Tailscale-Konto, und es geht kein Verkehr an
Tailscale.

Ein Fehler im übernommenen Verbindungscode kann Verbindungen stören oder
Adressen preisgeben. Ein Gerät aufnehmen kann er nicht, denn darunter prüft
WireGuard jedes Paket gegen die Schlüssel aus dem Log.

### Tailnet Lock {#tailnet-lock}

Mit [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock) antwortet
Tailscale selbst auf das Problem, dass man dem Koordinationsserver keine
Schlüssel anvertrauen möchte: Vertrauenswürdige Geräte signieren, welche
Schlüssel beitreten dürfen. Das Mitgliederlog übernimmt diesen Entwurf, eine
Kette signierter Einträge, ist aber juists eigener Code. Es
unterscheidet sich in drei Punkten:

- Im Log stehen die Mitglieder selbst, nicht nur die Schlüssel, die sie
  signieren.
- Jede Änderung braucht das Quorum, eine einzelne vertrauenswürdige Signatur
  reicht nicht.
- Die Geräte bringen die Änderungen selbst in eine Reihenfolge und verteilen
  sie untereinander. Tailnet Lock überlässt das dem Koordinationsserver.

## Das Mitgliederlog {#log}

Jede Änderung, etwa „nas aufnehmen“, ist ein Eintrag. Er enthält den Hash
des vorigen Eintrags und gilt erst, wenn genug Admins ihn mit ihren
[ML-DSA-44](https://doi.org/10.6028/NIST.FIPS.204)-Schlüsseln signiert
haben, die auch ein Quantencomputer nicht fälschen kann. Jedes Gerät geht
das Log vom ersten Eintrag des Netzes an durch und prüft jede Signatur
selbst.

Entstehen Änderungen gleichzeitig auf verschiedenen Geräten, bringt jedes
Gerät sie auf dieselbe Weise in eine Reihenfolge. Widersprechen sich zwei
Änderungen, löst juist das nie stillschweigend auf, mit einer Ausnahme: Das
Entfernen hat Vorrang. Gibt es einen echten Fork, also zwei Verläufe, die sich
nicht einig sind, wer Mitglied ist, schlägt juist Alarm, und ein Admin muss
ihn auflösen.

Jede Änderung an den Mitgliedern ersetzt das Gruppengeheimnis des Netzes. Das
neue Geheimnis wird für jedes Mitglied einzeln mit
[HPKE](https://www.rfc-editor.org/rfc/rfc9180) versiegelt, mit X25519 und
zusätzlich [ML-KEM-768](https://doi.org/10.6028/NIST.FIPS.203). Ein
entferntes Gerät kann deshalb nichts lesen, was mit dem neuen Geheimnis
geschützt ist.

## Geräte finden ohne Server {#discovery}

Damit Geräte einander finden, veröffentlichen sie ihre Adressen. Das
Gruppengeheimnis schützt diese Angaben:

- Im LAN beantworten Geräte Multicast-DNS-Anfragen nach einem Namen, der aus
  dem Gruppengeheimnis abgeleitet ist, und die Antwort ist verschlüsselt. Andere Geräte im
  LAN erfahren nur, dass dort juist läuft.
- Im öffentlichen BitTorrent-DHT legt jedes Mitglied seine signierte Adresse
  als veränderlichen Eintrag ab
  ([BEP 44](https://www.bittorrent.org/beps/bep_0044.html)). Nur Mitglieder
  können den Schlüssel berechnen, unter dem er liegt, und nur sie können ihn
  entschlüsseln.
- Mitglieder teilen einander mit, wo sie ein Gerät zuletzt erreicht haben.

Eine Einladung funktioniert schon, bevor das neue Gerät irgendein Geheimnis
kennt. Beide Seiten führen dazu [SPAKE2](https://www.rfc-editor.org/rfc/rfc9382)
aus, einen Schlüsselaustausch auf Basis eines kurzen Passworts, und
vereinbaren danach einen Schlüssel mit ML-KEM-768. Code oder Link lassen
sich nicht offline erraten, und ein Gerät, das sich dazwischenschaltet,
verrät sich durch die vier Wörter, die beide Seiten vergleichen.

## Quellen {#sources}

Zero Trust

- Scott Rose, Oliver Borchert, Stu Mitchell, Sean Connelly:
  [Zero Trust Architecture](https://doi.org/10.6028/NIST.SP.800-207),
  NIST SP 800-207, 2020
- Rory Ward, Betsy Beyer:
  [BeyondCorp: A New Approach to Enterprise Security](https://research.google/pubs/beyondcorp-a-new-approach-to-enterprise-security/),
  ;login:, 2014

WireGuard

- Jason A. Donenfeld:
  [WireGuard: Next Generation Kernel Network Tunnel](https://www.wireguard.com/papers/wireguard.pdf),
  NDSS 2017
- [WireGuard, Protokoll und Kryptografie](https://www.wireguard.com/protocol/)
- Trevor Perrin: [The Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- [wireguard-go](https://git.zx2c4.com/wireguard-go/) und
  [Tailscales Fork](https://github.com/tailscale/wireguard-go), den juist
  verwendet

Tailscale

- [How Tailscale works](https://tailscale.com/blog/how-tailscale-works)
- [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works)
- [DERP servers](https://tailscale.com/kb/1232/derp-servers)
- [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)
- [Der Quellcode des Tailscale-Clients](https://github.com/tailscale/tailscale)

Weitere Standards

- [RFC 9180, HPKE](https://www.rfc-editor.org/rfc/rfc9180)
- [FIPS 203, ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [RFC 9382, SPAKE2](https://www.rfc-editor.org/rfc/rfc9382)
- [FIPS 204, ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [BEP 44, Daten im BitTorrent-DHT ablegen](https://www.bittorrent.org/beps/bep_0044.html)

Den vollständigen Entwurf mit den Gründen für jede Entscheidung findest du im
[Architekturdokument](https://github.com/nning/juist/blob/main/docs/04-architecture.md)
und im [Bedrohungsmodell](https://github.com/nning/juist/blob/main/docs/02-threat-model.md)
des Repositorys (auf Englisch).

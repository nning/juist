---
title: juist im Vergleich
linkTitle: Im Vergleich
description: Worin sich juist von anderen Mesh-VPNs mit und ohne zentralen Server unterscheidet, und wann eines davon besser passt.
lead: Worin sich juist von anderen Mesh-VPNs unterscheidet, und wann eines davon besser zu dir passt.
---

## Der entscheidende Unterschied {#question}

Den Verkehr übertragen die meisten Mesh-VPNs ähnlich: über verschlüsselte
Tunnel zwischen den Geräten, direkt, wo das NAT es zulässt, und sonst über ein
Relay. Der Unterschied liegt darin, wer bestimmt, welche Geräte zum Netz
gehören, und wie man ein Gerät wieder hinauswirft.

Bei juist bestimmen das deine Admins, indem sie Änderungen im
[Mitgliederlog]({{< relref "docs/how-it-works" >}}#the-membership-log)
signieren, und jedes Gerät prüft diese Änderungen selbst. Dafür ist kein
Server nötig, und man muss niemandem vertrauen. Wie das aufgebaut ist,
erklärt die Seite [Architektur]({{< relref "docs/architecture" >}}).

Vier Dinge hat von den Meshes hier nur juist:

- **Keine zentrale Infrastruktur, und trotzdem WireGuard.** Die anderen
  Meshes ohne Server nutzen eigene Protokolle, und EasyTier bietet WireGuard
  nur als eine Möglichkeit unter mehreren. WireGuard allein kommt nicht durchs
  NAT.
- **Ein Admin-Quorum.** Du kannst für jede Änderung mehrere Admins verlangen.
  Dann kann keine einzelne Person ein Gerät aufnehmen.
- **Routing und Namen ohne Server.** Von den Meshes ohne Server
  veröffentlicht nur juist Dienste im Internet und lässt öffentliche Namen
  auf Mitglieder zeigen. Bei den anderen werden Routen und Namen von Hand in
  der Konfiguration jedes Geräts eingetragen, oder es gibt sie nicht.
- **Durchgehend quantensicher.** Jeder Tunnel mischt einen Schlüssel ein,
  den ein Quantencomputer nicht herausfinden kann, und jede Änderung am Netz
  ist mit ML-DSA signiert. Keines der anderen signiert seine Mitglieder so.
  Von den anderen Meshes bietet nur NetBird quantensichere Tunnel an, als
  experimentelle Option; reines WireGuard bekommt sie durch einen Preshared
  Key, den du von Hand setzt.

## Auf einen Blick {#overview}

EasyTier steht für die Meshes mit gemeinsamem Geheimnis.

{{< matrix >}}

## Tailscale {#tailscale}

[Tailscale](https://tailscale.com/blog/how-tailscale-works) hat Clients für
Linux, Windows, macOS, iOS und Android, Anmeldung über einen
Identitätsanbieter und
[Zugriffsregeln](https://tailscale.com/kb/1018/acls). juist enthält Teile
dieses Clients, siehe [Architektur]({{< relref "docs/architecture" >}}#tailscale).

Den Koordinationsserver betreibt Tailscale Inc., und er ist nicht Open
Source. Er kennt alle Geräte und verteilt die Schlüssel. Wer ihn
kontrolliert, könnte also ein eigenes Gerät einschleusen.
[Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock) schließt diese
Lücke: Geräte nehmen einen neuen Schlüssel nur an, wenn ein Schlüssel in
deiner Hand ihn signiert hat. Das Entfernen eines Geräts und das Verteilen der
Änderung laufen aber weiterhin über den Server. Seine Tunnel sind nicht
quantensicher: Es setzt keinen Preshared Key und lässt dich keinen setzen.

Tailscale passt, wenn du Clients für alle Plattformen und
Benutzerkonten mit Zugriffsregeln nach Benutzern brauchst und damit leben
kannst, dass der Server einer Firma in der Mitte steht.

## Headscale {#headscale}

[Headscale](https://github.com/juanfont/headscale) ist ein quelloffener
Koordinationsserver für die Tailscale-Clients, den du selbst betreibst. Du
musst dann deinem eigenen Server vertrauen statt dem von Tailscale.
Tailnet Lock unterstützt Headscale nicht
([Feature-Request](https://github.com/juanfont/headscale/issues/1307)). Die
Geräte übernehmen also ungeprüft, was der Server ihnen mitteilt.

Headscale passt, wenn du Tailscales Clients ohne Tailscales Server nutzen
willst und einen eigenen Server betreiben und absichern kannst.

## NetBird {#netbird}

[NetBird](https://docs.netbird.io/about-netbird/how-netbird-works) verbindet
Geräte über WireGuard. Koordiniert wird das von einem Management-Server, der
die Geräte, ihre Schlüssel und die Zugriffsregeln verwaltet. Du kannst den
Server von NetBird nutzen oder ihn mitsamt seinen Signal- und Relay-Servern
selbst betreiben. Der Client steht unter BSD-3-Clause, die Server unter
AGPL-3.0. Mit
[Rosenpass](https://docs.netbird.io/client/post-quantum-cryptography), einer
experimentellen Option, die es auf Handys nicht gibt, werden seine Tunnel
quantensicher.

NetBird passt, wenn du einen selbst betriebenen Server mit Dashboard,
Anmeldung über deinen Identitätsanbieter und Zugriffsregeln nach Benutzern
willst.

## Netmaker {#netmaker}

Auch [Netmaker](https://docs.netmaker.io/) baut sein Mesh aus WireGuard, unter
Linux und FreeBSD im Kernel, um einen Server herum, den du selbst betreibst
oder bei Netmaker mietest. Wie bei NetBird kennt dieser Server die Geräte und
verteilt ihre Schlüssel. Der Kern steht unter Apache-2.0. Die Anmeldung über
einen Identitätsanbieter und Ausweich-Relays gibt es in der
kostenpflichtigen Edition.

Netmaker passt, wenn du WireGuard im Kernel und einen eigenen Server willst.

## ZeroTier {#zerotier}

[ZeroTier](https://docs.zerotier.com/protocol) nutzt nicht WireGuard, sondern
ein eigenes Protokoll, und bildet ein Ethernet-Netz zwischen den Geräten
nach. Wer dazugehört, bestimmt ein
[Netzwerk-Controller](https://docs.zerotier.com/controller), entweder der von
ZeroTier oder dein eigener. Der Kern steht unter MPL-2.0. Der Quellcode des
Controllers ist zwar einsehbar, steht aber unter einer eigenen Lizenz von
ZeroTier, die die kommerzielle Nutzung einschränkt. ZeroTier One, der
quelloffene Client, ist nicht quantensicher; ZeroTier Quantum, eine eigene
kommerzielle Plattform von 2026, verspricht es zu sein.

ZeroTier passt, wenn du ein Layer-2-Netz brauchst, etwa für Broadcasts oder
für andere Protokolle als IP.

## Nebula {#nebula}

[Nebula](https://nebula.defined.net/docs/) stammt von Slack und kommt
ebenfalls ohne Server aus. Jedes Gerät hat ein Zertifikat deiner eigenen CA,
das seine Adresse und Gruppen enthält. Mitglieder mit öffentlicher Adresse
helfen den anderen, einander zu finden. Nebula steht unter MIT-Lizenz und
läuft auch in großen Installationen.

Was fehlt, ist ein Weg, ein Gerät wieder hinauszuwerfen. Jedes Gerät muss
eine [Sperrliste](https://nebula.defined.net/docs/config/pki/) auf anderem
Weg bekommen, etwa über ein Konfigurationsmanagement. Ein Gerät, das sie
nicht bekommen hat, akzeptiert das entfernte Gerät, bis dessen Zertifikat
abläuft. Bei juist ist das Entfernen eine
signierte Änderung, die die Geräte untereinander weitergeben. Ein
zusätzlicher Weg ist also nicht nötig.

Nebula passt, wenn deine Geräte ohnehin zentral verwaltet werden und du
Zugriffsregeln nach Gruppen willst.

## Tinc {#tinc}

[Tinc](https://www.tinc-vpn.org/) ist das älteste Mesh hier, das ohne Server
auskommt. Jedes Gerät hat für jedes Mitglied, mit dem es sich verbindet, eine
Datei mit dessen öffentlichem Schlüssel, und die Mitglieder geben weiter, was
sie über die übrigen wissen. Ein Mitglied mit öffentlicher Adresse hilft den
anderen durchs NAT und leitet ihren Verkehr bei Bedarf weiter. Um ein Gerät
zu entfernen, muss seine Datei von jedem Gerät verschwinden, das sie hat.
Version 1.0.37 ist wohl die letzte der Reihe 1.0, und 1.1 ist seit 2021 eine
Vorabversion.

Tinc passt für wenige Geräte, die du von Hand einrichtest, mit Software, die
seit Jahrzehnten läuft.

## rayfish {#rayfish}

[rayfish](https://github.com/rayfish/rayfish) ist das jüngste Mesh hier und
juist am nächsten: kein Konto und kein Server, dem man vertrauen muss. Ein
Netz ist ein Schlüsselpaar. Sein Coordinator nimmt Geräte per Einladung oder
nach Bestätigung auf und veröffentlicht die Liste der Mitglieder, signiert
mit dem Schlüssel des Netzes. Eine Entfernung erreicht die anderen auf
demselben Weg. Die Tunnel laufen nicht über WireGuard, sondern über das QUIC
von [iroh](https://www.iroh.computer/), und standardmäßig nutzt rayfish die
Relays und den pkarr-Server von n0, der Firma hinter iroh. Beides lässt sich
ersetzen.

Der Unterschied zu juist: Die Co-Coordinators von rayfish halten ein und
denselben Netzschlüssel. Wer eine Kopie davon hat, kann also allein alles
ändern. Bei juist hat jeder Admin einen eigenen Schlüssel, und eine Änderung
braucht k von ihnen. rayfish nennt sich selbst experimentell, vor 1.0 und
ohne Sicherheitsaudit.

Zwei weitere Projekte aus demselben Jahr gehen einen ähnlichen Weg:
[nostr-vpn](https://github.com/mmalmi/nostr-vpn), dessen Geräte eine Liste
der Mitglieder nur annehmen, wenn einer seiner Admins sie signiert hat, und
der Direct-Modus von [Tunnet](https://github.com/tunnetio/Tunnet), mit
signierten Mitgliedern und Widerrufen in einem Dokument, das die Geräte
untereinander abgleichen. Bei beiden kann ein einzelner Admin oder
Coordinator jede Änderung vornehmen.

rayfish passt, wenn du ein Mesh ohne Server auf Plattformen ausprobieren
willst, die juist fehlen, etwa Windows oder macOS.

## Meshes mit gemeinsamem Geheimnis {#shared-secret}

Projekte wie [EasyTier](https://github.com/EasyTier/EasyTier) nehmen jeden
auf, der den Namen und das Geheimnis des Netzes kennt. Das ist schnell
eingerichtet, aber Geräte werden nicht einzeln aufgenommen, und niemand hält
fest, wer sie aufgenommen hat. Um ein Gerät zu entfernen, muss das Geheimnis
auf allen anderen Geräten geändert werden.

## Reines WireGuard {#wireguard}

[WireGuard](https://www.wireguard.com/quickstart/) allein verbindet nur
Geräte, deren Schlüssel und Adressen du jeweils in die Konfiguration der
anderen eingetragen hast. Dazwischen gibt es nichts, dem man vertrauen müsste,
und im Kernel ist es schneller als juist, das WireGuard im Userspace
betreibt. Dafür musst du für jedes neue Gerät alle anderen anpassen, stehen
beide Seiten hinter NAT, kommt keine Verbindung zustande, und ein Relay gibt
es nicht. Ein Preshared Key, von Hand gesetzt oder von Rosenpass erneuert,
macht seine Tunnel quantensicher.

Reines WireGuard passt für wenige Geräte mit festen öffentlichen Adressen.

## Nicht verglichen {#elsewhere}

Manche Projekte, die oft in einem Atemzug mit diesen genannt werden, lösen
eine andere Aufgabe. Pangolin, Firezone, Twingate und Defguard verbinden
Geräte mit Gateways und Diensten statt miteinander, und Cloudflare Mesh
leitet allen Verkehr durch das Netz von Cloudflare. Yggdrasil, cjdns und
Mycelium sind ein einziges offenes Netz, dem jeder beitreten kann. Hamachi
und Radmin VPN sind für Spiele im LAN gemacht. EdgeVPN, hyprspace und wgmesh
nehmen jeden auf, der ein gemeinsames Geheimnis kennt oder in einer von Hand
geschriebenen Liste steht, wie die Meshes mit gemeinsamem Geheimnis oben.
innernet ist wie juist ein Kommandozeilenwerkzeug für Linux, aber um einen
Server herum, der bestimmt, wer dazugehört.

## Wo juist schwächer ist {#weaker}

- Ein Sicherheitsaudit gab es für juist bisher nicht.
- Es läuft unter Linux und FreeBSD, und unter Android als Mitglied ohne
  öffentliche Namen, Rollen und Subnetze, das kein Exit-Node sein kann. Für Windows,
  macOS und iOS gibt es nichts.
- Es kennt nur Geräte, keine Benutzer: Seine Zugriffsregeln nennen Geräte,
  und eine Anmeldung über einen Identitätsanbieter gibt es nicht.
- Ein entferntes Gerät ist draußen, sobald die anderen Geräte davon erfahren.
  Ein abgeschnittenes Gerät erfährt es aber womöglich erst nach bis zu 48
  Stunden. Ein zentraler Server teilt es jedem Gerät, das er erreicht, sofort
  mit.
- Es ist für Netze mit 25 bis 100 Geräten und wenigen Admins gedacht.

## Quellen {#sources}

- [How Tailscale works](https://tailscale.com/blog/how-tailscale-works),
  [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock),
  [Tailscales Open Source](https://tailscale.com/opensource)
- [Headscale](https://github.com/juanfont/headscale) und der
  [Feature-Request für Tailnet Lock](https://github.com/juanfont/headscale/issues/1307)
- [How NetBird works](https://docs.netbird.io/about-netbird/how-netbird-works),
  [NetBirds Lizenz](https://github.com/netbirdio/netbird/blob/main/LICENSE)
- [ZeroTiers Protokoll](https://docs.zerotier.com/protocol),
  [Netzwerk-Controller](https://docs.zerotier.com/controller),
  [Lizenz](https://github.com/zerotier/ZeroTierOne/blob/dev/LICENSE.txt)
- [Nebulas Dokumentation](https://nebula.defined.net/docs/), seine
  [PKI und Sperrliste](https://nebula.defined.net/docs/config/pki/),
  [Introducing Nebula](https://slack.engineering/introducing-nebula-the-open-source-global-overlay-network-from-slack/)
- [WireGuard Quick Start](https://www.wireguard.com/quickstart/)
- [NAT-Traversal bei Netmaker](https://docs.netmaker.io/docs/how-to-guides/nat-traversal),
  [Anmeldung über OAuth](https://docs.netmaker.io/docs/server-installation/integrating-oauth),
  [Clients](https://docs.netmaker.io/docs/client-installation)
- [Tinc](https://www.tinc-vpn.org/)
- [rayfish](https://github.com/rayfish/rayfish) und sein
  [Sicherheitsmodell](https://github.com/rayfish/rayfish/blob/main/SECURITY.md),
  [Protokoll von nostr-vpn](https://github.com/mmalmi/nostr-vpn/blob/main/docs/protocol.md),
  [Tunnet](https://github.com/tunnetio/Tunnet)
- [Headscale und OIDC](https://headscale.net/stable/ref/oidc/),
  [NetBird mit WireGuard im Kernel und im Userspace](https://docs.netbird.io/help/troubleshooting-client),
  [ZeroTiers SSO](https://docs.zerotier.com/sso/),
  [Mobile Nebula](https://github.com/DefinedNet/mobile_nebula),
  [EasyTiers Zugriffsregeln](https://easytier.rs/en/guide/config/acl.html)
- [EasyTier](https://github.com/EasyTier/EasyTier)
- Routing und Namen:
  [Exit-Nodes bei Tailscale](https://tailscale.com/kb/1103/exit-nodes),
  [DNS](https://tailscale.com/kb/1054/dns),
  [Funnel](https://tailscale.com/kb/1223/funnel) und
  [ein Tailnet zur Zeit](https://tailscale.com/kb/1225/fast-user-switching);
  [Funktionen von Headscale](https://headscale.net/stable/about/features/);
  [Custom Zones](https://docs.netbird.io/manage/dns/custom-zones),
  [Reverse Proxy](https://docs.netbird.io/manage/reverse-proxy) und
  [Profile](https://docs.netbird.io/client/profiles) bei NetBird;
  [DNS bei Netmaker](https://docs.netmaker.io/docs/features/dns);
  [Exit-Node](https://docs.zerotier.com/exitnode) und
  [DNS](https://docs.zerotier.com/dns/) bei ZeroTier;
  [Unsafe Routes](https://nebula.defined.net/docs/guides/unsafe_routes/)
  und [Lighthouse-DNS](https://nebula.defined.net/docs/config/lighthouse/) bei Nebula;
  [Tinc als Gateway](https://www.tinc-vpn.org/examples/redirect-gateway/);
  [Exit-Nodes bei rayfish](https://rayfish.xyz/docs/11-exit-nodes);
  [Magic DNS bei EasyTier](https://easytier.rs/en/guide/network/magic-dns.html)
- Gegen einen Quantencomputer:
  [Tailscale](https://tailscale.com/docs/concepts/post-quantum-cryptography),
  [NetBird mit Rosenpass](https://docs.netbird.io/client/post-quantum-cryptography),
  [ZeroTier Quantum](https://www.zerotier.com/news/rsac-2026-zerotier-launches-zerotier-quantum-the-worlds-first-end-to-end-quantum-secure-networking-platform/),
  [Nebulas Feature-Request](https://github.com/slackhq/nebula/issues/1446),
  [Handshakes bei iroh](https://iroh.computer/blog/iroh-post-quantum-handshakes),
  [Grenzen von WireGuard](https://www.wireguard.com/known-limitations/)
- Nur HTTPS und Layer 2:
  [DERP-Server bei Tailscale](https://tailscale.com/kb/1232/derp-servers),
  [Relays bei NetBird](https://docs.netbird.io/about-netbird/understanding-nat-and-connectivity),
  [Netmaker 1.7](https://github.com/gravitl/netmaker/releases/tag/v1.7.0),
  [TCP-Relay bei ZeroTier](https://docs.zerotier.com/relay/),
  [Konfiguration von Tinc](https://www.tinc-vpn.org/documentation-1.1/Main-configuration-variables.html),
  [Relays bei iroh](https://docs.iroh.computer/configuring-networks),
  [Nebula und Layer 2](https://github.com/slackhq/nebula/issues/1452),
  [EasyTier und Layer 2](https://github.com/EasyTier/EasyTier/issues/184)

Die Recherche hinter dieser Seite umfasst rund 25 Projekte und steht im
Repository (auf Englisch):
[Control-Plane-Optionen](https://github.com/nning/juist/blob/main/docs/03-control-plane-options.md)
und
[Projektübersicht](https://github.com/nning/juist/blob/main/docs/research/project-survey.md).

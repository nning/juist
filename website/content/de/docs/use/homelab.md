---
title: Das Homelab im Internet
linkTitle: Das Homelab im Internet
description: Einen Dienst auf deinem NAS oder Heimserver unter einem Namen aus dem Internet erreichbar machen, hinter CGNAT oder DS-Lite und ohne Portfreigabe am Router.
lead: Dein Anbieter gibt dir keine öffentliche IPv4-Adresse, oder du willst zu Hause keinen Port öffnen. Ein kleiner VPS in deinem Netz nimmt die Verbindungen für docs.example.org an und reicht sie durch den Tunnel an dein NAS weiter, wo TLS endet.
---

## Was du bekommst

`docs.example.org` lässt sich in jedem Browser öffnen, und das NAS zu Hause
liefert die Seite aus. Das NAS baut die Verbindung zum VPS selbst auf, dein
Router öffnet also keinen Port, und seine Adresse steht in keinem
öffentlichen DNS-Eintrag. Der VPS, der **Ingress**, liest nur den Namen, den
ein Browser anfragt, und reicht die Verbindung weiter. TLS endet erst auf dem
NAS, mit einem Zertifikat von Let's Encrypt, der Ingress sieht den Inhalt
also nie.

Mitglieder des Netzes gehen nicht über den Ingress, sondern erreichen den
Namen direkt am NAS, durch den Tunnel.

## Was du brauchst

- Eine Domain, hier `example.org`, und Zugriff auf ihre DNS-Einträge.
- Einen VPS mit öffentlicher Adresse unter Linux oder FreeBSD, der Mitglied
  des Netzes ist. Öffne dort 41643/udp, mit `sudo ufw allow juist`, damit
  sich das NAS direkt mit ihm verbindet ([Ports]({{< relref "docs/relays" >}}#ports)).
- Das NAS unter Linux oder FreeBSD, mit dem Dienst auf einem lokalen Port,
  hier `127.0.0.1:8080`.

## Einrichten

{{< step on="dem Gerät eines Admins" >}}
Leg die Domain des Netzes fest und mach den VPS zum Ingress:

```sh
juist network domain example.org
juist grant vps ingress
```
{{< /step >}}

{{< step on="der Website deines DNS-Anbieters" >}}
Lass `*.example.org` auf die öffentliche Adresse des VPS verweisen, oder nur
`docs.example.org`.
{{< /step >}}

{{< step on="vps" as="der Ingress" >}}
```sh
juist ingress serve
```

Der Befehl fragt einmal nach sudo, startet den Ingress und öffnet 443 und 80
in firewalld oder ufw.
{{< /step >}}

{{< step on="nas" as="dem Ziel" >}}
Veröffentliche den Namen, mit HTTP/3 für Browser, die es können:

```sh
juist publish add docs 127.0.0.1:8080 --http3
```

Die Ausgabe lautet `ending TLS for docs.example.org to 127.0.0.1:8080, with HTTP/3`.
Danach folgen zwei DNS-Einträge für deinen DNS-Anbieter. Mit dem
HTTPS-Eintrag beginnen Browser gleich mit HTTP/3. Der CAA-Eintrag bindet die
Zertifikate des Namens an das ACME-Konto dieses Geräts.
{{< /step >}}

## Darauf achten

- **Trag den CAA-Eintrag ein.** Ohne ihn könnte sich, wer den Ingress
  kontrolliert, ein Zertifikat für deinen Namen holen und den Verkehr von
  Besuchern aus dem Internet mitlesen.
- **Ein veröffentlichter Server erreicht nach einem Einbruch dein Netz.** Das
  NAS ist ein vollwertiges Mitglied. Veröffentliche von dort nur, was du
  ohnehin ins Internet stellen würdest, und betreibe alles andere als
  [Service-Mitglied]({{< relref "docs/service-member" >}}),
  von dem kein Gerät Verbindungen annimmt.
- **Der Ingress sieht den Namen, die Adresse des Clients, Datenmengen und
  Zeitpunkte** und protokolliert jede Verbindung in einer Zeile.
- **Veröffentlichen ist eine Änderung der Admins.** Hat das NAS keinen
  Admin-Schlüssel, nennt der Befehl den, den ein Admin ausführt.

## Weiterlesen

- [Dienste veröffentlichen]({{< relref "docs/publishing" >}}): alle Optionen,
  der Ingress, Grenzen
- [HTTP/3]({{< relref "docs/publishing" >}}#http3)
- [Spieleserver und andere TCP-Dienste]({{< relref "docs/tcp-services" >}})

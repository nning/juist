---
title: Aus abgeschotteten Netzen
linkTitle: Aus abgeschotteten Netzen
description: Dein Netz aus einem Hotel-, Firmen- oder Schulnetz erreichen, das nichts als HTTPS hinauslässt, über ein Relay auf Port 443 und, wo es einen gibt, über den Proxy der Firma.
lead: Das Hotel-WLAN lässt nichts als HTTPS hinaus, das Firmennetz nur seinen Proxy. Ein Relay von dir auf Port 443 bringt deinen Laptop trotzdem durch, wie einen HTTPS-Client unter vielen.
---

## Was du bekommst

Dein Laptop erreicht jedes Mitglied auch aus einem Netz, das WireGuard, die
Pfadsuche und den üblichen Port des Relays sperrt. Sein Verkehr geht per TLS
an ein Relay von dir auf Port 443, unter einem öffentlichen Namen wie
`relay.example.org`. Meist braucht der Laptop dafür keine Einstellung:
Erreicht er den üblichen Port des Relays nicht, wechselt er von selbst zum
Namen.

Ein Netz, das den Verkehr prüft oder nur über einen Proxy hinauslässt,
braucht eine Einstellung mehr auf dem Laptop.

## Was du brauchst

- Ein [Relay]({{< relref "docs/relays" >}}) mit öffentlicher Adresse, etwa
  einen kleinen VPS, und einen Namen, den du darauf verweisen lassen kannst.
- Hat das Netz einen [Ingress]({{< relref "docs/publishing" >}}), der auch
  Relay ist, hast du schon eines: Sein Relay bedient `relay.` plus die Domain
  des Netzes auf 443.

## Einrichten

{{< step on="deinem DNS" >}}
Lass einen Namen wie `relay.example.org` auf das Relay verweisen, mit einem
A-Eintrag und, wenn das Relay IPv6 hat, einem AAAA-Eintrag.
{{< /step >}}

{{< step on="vps" as="dem Relay" >}}
Lass das Relay den Namen auf 443 bedienen:

```sh
sudo juist set --relay-name relay.example.org
```

Let's Encrypt stellt ein Zertifikat dafür aus, und jedes Gerät erfährt den
Namen. `juist status` zeigt `Relay name    relay.example.org, on 443`.
{{< /step >}}

{{< step on="laptop" as="dem Gerät im Hotel" >}}
Sperrt das Netz nur Ports, ist hier nichts zu tun. Prüft es auch den
Verkehr, sende nur noch HTTPS:

```sh
sudo juist set --https-only
```

Die Ausgabe lautet `https only`. Geht der Verkehr nur über den Proxy der
Firma hinaus, gib juist auch den Proxy an und tipp seine URL ein, wenn juist
danach fragt:

```sh
sudo juist set --https-only --proxy -
```

Zurück in einem offenen Netz lässt `sudo juist set --https-only=false` die
Tunnel wieder direkt laufen.
{{< /step >}}

## Darauf achten

- **Alles läuft über das Relay**, das damit die Geschwindigkeit begrenzt, und
  das TCP im Tunnel läuft in TCP, das sich nur langsam von Paketverlust
  erholt. Ein zweites Relay auf 443 an einem anderen Ort hält den Laptop
  erreichbar, wenn eines ausfällt.
- **Beitreten aus einem solchen Netz** braucht `--https-only` vor
  `juist join` und den Einladungslink. Ein Code funktioniert nicht: Er braucht
  das LAN, das der Nur-HTTPS-Modus nicht durchsucht.
- **juist bleibt erkennbar** für einen Zensor, der Server abfragt oder
  TLS-Fingerabdrücke vergleicht.
- **Ein CAA-Eintrag für den Namen des Relays** muss Let's Encrypt zulassen.
- **Die Android-App** hat keine Einstellung für den Nur-HTTPS-Modus, wechselt
  aber von selbst zum Namen eines Relays auf 443, wo UDP und der Port des
  Relays gesperrt sind.

## Weiterlesen

- [Netze, die nur HTTPS durchlassen]({{< relref "docs/https-only" >}}): der
  Proxy und was `juist health` meldet
- [Ein Relay auf 443]({{< relref "docs/relays" >}}#ein-relay-auf-443)

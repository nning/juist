---
title: Sicher im fremden WLAN
linkTitle: Sicher im fremden WLAN
description: Im Café, im Hotel oder im Zug den Internetverkehr und das DNS über den eigenen VPS oder den Anschluss zu Hause schicken, damit das WLAN nur verschlüsselten Verkehr sieht.
lead: Das WLAN des Cafés muss nicht sehen, wohin du gehst. Dein Laptop oder Telefon schickt seinen Internetverkehr durch den Tunnel zu deinem eigenen VPS oder zu deinem Anschluss zu Hause und geht von dort ins Internet.
---

## Was du bekommst

Im WLAN des Cafés schickt dein Laptop seinen Internetverkehr und sein DNS an
ein Mitglied deines Netzes, den [Exit-Node]({{< relref "docs/exit-nodes" >}}),
der ihn weiterschickt. Das WLAN sieht nur verschlüsselten Verkehr zum
Exit-Node. Websites sehen die Adresse des Exit-Nodes: die deines VPS oder
deine eigene zu Hause.

Im Beispiel heißt der VPS `vps`. Ein NAS oder ein kleiner Server zu Hause
funktioniert genauso.

## Was du brauchst

- Ein Netz, in dem der Laptop oder das Telefon ist ([das erste Netz]({{< relref "docs/first-network" >}})).
- Ein Mitglied, das eingeschaltet bleibt, unter Linux oder unter FreeBSD mit
  pf, als Exit-Node.
- Auf dem Gerät, mit dem du unterwegs bist: Linux, FreeBSD oder die
  [Android-App]({{< relref "docs/android" >}}).

## Einrichten

{{< step on="dem Gerät eines Admins" >}}
Gib dem VPS die Rolle:

```sh
juist grant vps exit
```

Das ist eine Änderung am Netz, die die Admins bestätigen.
{{< /step >}}

{{< step on="vps" as="dem Exit-Node" >}}
Stimme zu, den Internetverkehr des Netzes zu übernehmen:

```sh
juist exit serve
```

Beim ersten Mal fragt es, ob es ein Einrichtungsskript mit sudo ausführen
darf. Danach lautet die Ausgabe `serving as an exit node`.
{{< /step >}}

{{< step on="laptop" >}}
Im WLAN des Cafés:

```sh
juist exit use vps
```

Die Ausgabe lautet `internet via vps`, und die Zeile `Exit node` in
`juist status` sagt `vps, DNS too`. Zu Hause geht der Laptop mit
`juist exit off` wieder direkt ins Internet, die Ausgabe lautet dann
`internet direct`. Auf dem Telefon wählst du `vps` unter **Internet** auf
dem Statusbildschirm der App.
{{< /step >}}

## Darauf achten

- **Melde dich zuerst auf der Portalseite des WLANs an.** Solange der
  Exit-Node nicht erreichbar ist, wird der Internetverkehr des Laptops
  blockiert, nicht direkt geschickt.
- **Ist der Exit-Node weg, ist es auch dein Internet.** Das ist Absicht: An
  ihm vorbei geht nichts hinaus. `juist exit off` schickt den Verkehr wieder
  direkt.
- **Der Exit-Node sieht, was du durch ihn schickst**, wie jeder
  VPN-Anbieter. Nimm ein Gerät, dem du vertraust.
- **Dein LAN und die Geräte des Netzes bleiben direkt**, ebenso Antworten
  auf Verbindungen aus dem Internet, etwa auf eine ssh-Sitzung zum Laptop.
  `juist exit use vps --isolate` schickt auch diese Antworten über den
  Exit-Node.

## Weiterlesen

- [Exit-Nodes]({{< relref "docs/exit-nodes" >}}): was über den Exit-Node
  läuft und jeder Grund, aus dem er nicht nutzbar ist
- [Android]({{< relref "docs/android" >}}): ein Exit-Node auf dem Telefon
- [Zugriffsregeln]({{< relref "docs/access" >}}): welche Geräte welchen
  Exit-Node nutzen dürfen

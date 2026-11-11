---
title: Ein Spieleserver für Freunde
linkTitle: Ein Spieleserver für Freunde
description: Einen Spieleserver zu Hause betreiben und Freunde unter einem eigenen Namen darauf spielen lassen, ohne Portfreigabe am Router, über einen Ingress oder direkt durch den Tunnel.
lead: Dein Minecraft-Server läuft auf dem NAS zu Hause, hinter einem Router ohne Portfreigabe. Freunde verbinden sich trotzdem mit mc.example.org:25565, über deinen Ingress, und Freunde in deinem Netz direkt durch den Tunnel.
---

## Was du bekommst

Ein Server, der kein TLS spricht, etwa die Java Edition von Minecraft,
bekommt einen eigenen Port auf jedem [Ingress]({{< relref "docs/publishing" >}}),
dem Mitglied mit öffentlicher Adresse, das Verbindungen weiterreicht.
Freunde ohne juist verbinden sich mit `mc.example.org:25565`, und der Ingress
reicht jede Verbindung durch den Tunnel an das NAS weiter, ohne sie zu
lesen. Dein Router gibt keinen Port frei, und deine Adresse zu Hause steht in
keinem öffentlichen Eintrag.

Freunde, die Mitglied deines Netzes sind, erreichen den Server direkt am
NAS, solange der öffentliche Port der des NAS ist und der Name kein
`--proxy` hat.

## Was du brauchst

- Ein Netz mit Domain und Ingress, einmal eingerichtet wie in den Schritten
  1 bis 3 unter [Dienste veröffentlichen]({{< relref "docs/publishing" >}}#setting-it-up).
- Den Spieleserver auf einem Mitglied, hier `nas`.

## Einrichten

{{< step on="nas" as="dem Spieleserver" >}}
Veröffentliche den Port des Servers auf jedem Ingress:

```sh
juist publish mc 25565 --tcp
```

Die Ausgabe lautet `nas: publishes mc.example.org:25565/tcp` und
`passing mc.example.org to 127.0.0.1:25565`: juist reicht dem Server die
Bytes unverändert weiter. Mit `--tcp=PORT` nimmst du einen anderen
öffentlichen Port. Hat das NAS keinen Admin-Schlüssel, nennt der Befehl, was
ein Admin ausführt: `juist publish mc 25565 --tcp --on nas`.

Lauscht der Server auf allen Adressen, nimmt er die Verbindungen selbst an.
Dann veröffentlicht ein Admin den Port des NAS mit
`juist publish mc 25565 --tcp --on nas`, und du bedienst ihn hier mit
`juist publish mc`.
{{< /step >}}

{{< step on="der Website deines DNS-Anbieters" >}}
Bei Bedarf, für Clients, die einen SRV-Eintrag nachschlagen, wie Minecraft
bei einem Namen ohne Port:

```text
_minecraft._tcp.mc.example.org. SRV 0 5 25565 mc.example.org.
```
{{< /step >}}

## Darauf achten

- **Nur TCP.** Der Ingress reicht kein UDP weiter, 19132/udp von Minecraft
  Bedrock ist aus dem Internet also nicht erreichbar. Freunde in deinem Netz
  erreichen das NAS durch den Tunnel, und dort kommt auch UDP durch.
- **Der Ingress sieht, was das Protokoll nicht verschlüsselt.** Veröffentliche
  so nur, was sich selbst verschlüsselt oder was jeder sehen darf.
- **Der Server steht im Internet.** Wer den Namen findet, kann sich
  verbinden, also nutze die Whitelist des Spiels. Ein Server, dem du keinen
  Zugang zu deinem Netz zutraust, gehört auf ein eigenes Mitglied
  ([Den Server vom Netz fernhalten]({{< relref "docs/service-member" >}})).
- **Freunde im Netz erreichen jeden Port jedes Geräts**, solange keine
  [Zugriffsregeln]({{< relref "docs/access" >}}) etwas anderes sagen, etwa
  `pass from <friends> to nas proto tcp port 25565`.
- **Adressen der Clients.** Der Server sieht Verbindungen vom Ingress. Mit
  `--proxy` an `juist publish` kommt die Adresse des Clients in einem
  Header nach PROXY-Protokoll v2 mit. Paper und Velocity nehmen ihn, wenn man
  es einstellt, Vanilla-Minecraft nicht.
- Die Ports 80, 443 und juists eigene, 41640 bis 41739, lassen sich so nicht
  veröffentlichen.

## Weiterlesen

- [Spieleserver und andere TCP-Dienste]({{< relref "docs/tcp-services" >}})
- [Geräte einladen]({{< relref "docs/invites" >}}), um Freunde ins Netz zu holen

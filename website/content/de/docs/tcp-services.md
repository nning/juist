---
title: TCP-Dienste
linkTitle: TCP-Dienste
description: Einen Spieleserver oder einen anderen Dienst ohne TLS auf einem eigenen Port jedes Ingress veröffentlichen.
lead: Ein Dienst ohne TLS, etwa ein Minecraft-Server, bekommt einen eigenen Port auf jedem Ingress. Der Ingress reicht jede Verbindung direkt an das Gerät weiter, ohne mitzulesen.
status: [Linux, FreeBSD]
---

## Einrichten

Du brauchst eine Domain und einen Ingress, wie sie
[Dienste veröffentlichen]({{< relref "docs/publishing" >}}#setting-it-up)
einrichtet.

Auf dem NAS, als dessen [Operator]({{< relref "docs/operator" >}}):

```sh {device="nas"}
juist publish mc 25565 --tcp
```

Das veröffentlicht den Minecraft-Server auf Port 25565 des NAS auf Port 25565
jedes Ingress, als `mc.example.org`. Die Ausgabe lautet
`nas: publishes mc.example.org:25565/tcp` und
`passing mc.example.org to 127.0.0.1:25565`. `--tcp=PORT` wählt einen anderen
öffentlichen Port: `juist publish ssh 22 --tcp=2222` veröffentlicht den
SSH-Zugang des NAS als `ssh.example.org:2222/tcp`. Hat das NAS keinen
Admin-Schlüssel, nennt der Befehl den Befehl für einen Admin, wie bei
[jedem Namen]({{< relref "docs/publishing" >}}#who-publishes).

Ein Dienst, der auf allen Adressen lauscht, auch auf den Overlay-Adressen,
nimmt seine Verbindungen dort selbst an. Dann veröffentlicht ein Admin den
Port des Geräts mit `--on`, und der Operator des NAS bedient ihn, so wie er
ist:

```sh
juist publish mc 25565 --tcp --on nas   # auf dem Gerät eines Admins
juist publish mc                        # auf nas
```

`juist publish ssh 22 --tcp=2222 --on nas` gibt
`ssh.example.org:2222/tcp to 22` aus.

Spieler verbinden sich mit `mc.example.org:25565`. Jeder Ingress lauscht auf
dem Port, solange ein Name darauf veröffentlicht ist. Unter Linux öffnet der
Ingress den Port in firewalld oder ufw und schließt ihn wieder, wenn der Name
entfällt. `juist status` auf dem Ingress listet diese Ports auf, auch solche,
die ein anderes Programm belegt.

{{< note caution >}}
Der Ingress sieht alles, was ein Protokoll überträgt, wenn das Protokoll
nicht selbst verschlüsselt, und ein CAA-Eintrag hilft dort nicht.
Veröffentliche so nur, was selbst verschlüsselt, wie SSH, oder was jeder
sehen darf.
{{< /note >}}

## Gut zu wissen

- Nur Admins können einen TCP-Port veröffentlichen. Die Rolle `publish` teilt
  nur auf 443.
- Jeder öffentliche Port gehört zu einem Namen. Abgelehnt werden die Ports 80
  und 443, die Ports von juist selbst, 41640 bis 41739, und ein Port, den ein
  Ingress für einen eigenen Namen nutzt.
- Mitglieder erreichen den Namen direkt bei seinem Gerät, wenn der öffentliche
  Port dem Port auf dem Gerät gleicht und kein `--proxy` gesetzt ist. Sonst
  gehen sie über den Ingress.
- `--proxy` schickt zuerst die Adresse des Clients in einem
  PROXY-Protokoll-v2-Header, den der Dienst erwarten muss. Paper und Velocity
  tun das, wenn sie so eingestellt sind; Vanilla-Minecraft nicht.
- juist gibt keinen SRV-Eintrag aus. Clients, die einen suchen, wie Minecraft
  bei einem Namen ohne Port, brauchen ihn bei deinem DNS-Anbieter:
  `_minecraft._tcp.mc.example.org. SRV 0 5 25565 mc.example.org.`
- UDP wird nicht weitergereicht, also auch nicht 19132/udp von Minecraft
  Bedrock.

## Fehlersuche

| Du siehst | Was zu tun ist |
|---|---|
| `another program holds port 25565 on …, needed for NAME` | Der Dienst lauscht auf allen Adressen, auch auf den Overlay-Adressen. Veröffentliche stattdessen den Port des Geräts, wie der Hinweis sagt, und bediene ihn mit `juist publish NAME` auf dem Gerät. |
| auf vps, `juist status`: `Ingress` zeigt `…; another program holds port 22` | Ein Programm auf dem Ingress, oft sshd, belegt einen veröffentlichten Port. juist überlässt ihm den Port. Veröffentliche den Namen mit `--tcp=PORT` auf einem anderen Port. |

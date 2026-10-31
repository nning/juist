---
title: Eigene Dienste durch den Tunnel
linkTitle: Eigene Dienste durch den Tunnel
description: Den eigenen Mailserver, die Nextcloud oder den Git-Server unter dem gewohnten Namen durch den Tunnel erreichen, während das Internet sie weiter erreicht wie bisher.
lead: Dein Mailserver heißt mail.example.org, für dich und für alle anderen. Läuft juist auf dem Server und auf deinem Laptop, erreicht der Laptop denselben Namen durch den Tunnel. Das Zertifikat passt weiterhin, und sonst merkt niemand etwas.
---

## Was du bekommst

Deine Mailprogramme behalten `mail.example.org` als Server. Auf einem
Laptop, der [öffentliche Namen]({{< relref "docs/names" >}}) eingeschaltet
hat, führt der Name zur Adresse des Servers im Netz, IMAP und der Versand
laufen also durch den Tunnel. Ist der Server über das Netz nicht erreichbar,
nimmt der Laptop wieder seine öffentliche Adresse, wie ohne juist.

Im Beispiel heißt der Mailserver `mail`. Eine Nextcloud, ein Git-Server oder
jeder andere Dienst unter einem eigenen Namen funktioniert genauso.

## Was du brauchst

- Ein Netz, in dem der Laptop ist ([das erste Netz]({{< relref "docs/first-network" >}})).
- Den Server unter Linux oder FreeBSD. Hat er eine öffentliche Adresse,
  öffne dort 41643/udp, mit `sudo ufw allow juist` oder
  `sudo firewall-cmd --permanent --add-service=juist && sudo firewall-cmd --reload`,
  damit sich die Geräte direkt mit ihm verbinden ([Ports]({{< relref "docs/relays" >}})).
- Laptops unter Linux oder FreeBSD. Die Android-App löst keine öffentlichen
  Namen auf.

## Einrichten

{{< step on="mail" as="dem Server" >}}
[Installiere juist]({{< relref "docs/install" >}}) und tritt dem Netz mit
einer [Einladung]({{< relref "docs/invites" >}}) bei. Lass dann das DNS des
Servers, wie es war, denn er muss nur erreichbar sein:

```sh
sudo juist set --dns=false
```

Die Ausgabe lautet `dns off`. Ohne das beantwortet juistd auf einem Host
ohne systemd-resolved das gesamte DNS des Hosts, und die Abfragen des
Mailservers nach Blocklisten, SPF und DANE liefen über juistd.
{{< /step >}}

{{< step on="dem Gerät eines Admins" >}}
Lass den Namen auf den Server verweisen:

```sh
juist names add mail mail.example.org
```

Weitere Namen wie `imap.example.org` kommen genauso dazu, bis zu 32 pro
Gerät. Jeder ist eine Änderung am Netz, die die Admins bestätigen.
{{< /step >}}

{{< step on="jedem Laptop" >}}
Schalte öffentliche Namen ein:

```sh
juist names on
```

Die Ausgabe lautet `public names on: mail.example.org at mail`.
`juist names` zeigt, wie dieser Laptop jeden Namen auflöst.
{{< /step >}}

## Darauf achten

- **Jedes Mitglied erreicht jeden Port des Servers.** Das Paket lässt den
  Verkehr auf `juist0` durch ufw und firewalld. Ohne
  [Zugriffsregeln]({{< relref "docs/access" >}}) steht dann ein Admin-Panel,
  die Weboberfläche eines Spamfilters oder eine Datenbank, die auf allen
  Adressen lauscht, jedem Mitglied offen. Zugriffsregeln schränken das ein,
  zum Beispiel:

  ```text
  table <laptops> { laptop, laptop2 }

  pass from <laptops> to mail proto tcp port { 993, 465, 587 }
  ```

  Sie gelten für das ganze Netz: Was keine Regel durchlässt, wird zwischen
  allen Geräten abgewiesen.
- **Der Dienst muss auf der Adresse des Servers im Netz lauschen.** Postfix
  und Dovecot lauschen von sich aus auf allen Adressen. Ein Dienst, der nur
  an die öffentliche Adresse gebunden ist, antwortet nicht durch den Tunnel.
- **Clients kommen jetzt von den Adressen des Netzes**, etwa `198.18.36.4`.
  Trag sie nicht in `mynetworks` von Postfix oder eine andere Liste
  vertrauenswürdiger Netze ein: Dann könnte jedes Mitglied ohne Anmeldung
  Mail verschicken. Auch Rate-Limits und fail2ban sehen diese Adressen.
- **Kein Exit-Node auf dem Server.** Mit `juist exit use` ginge ausgehende
  Mail von der Adresse des Exit-Nodes hinaus, und SPF und Reverse-DNS
  passten nicht mehr.

## Weiterlesen

- [Namen]({{< relref "docs/names" >}}): warum jedes Gerät selbst zustimmt
  und wie ein Gerät Namen auflöst
- [Zugriffsregeln]({{< relref "docs/access" >}})
- [Was das Paket installiert]({{< relref "docs/install" >}})

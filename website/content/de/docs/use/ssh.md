---
title: Server ohne offenes SSH
linkTitle: Server ohne offenes SSH
description: Port 22 zum Internet schließen und die eigenen Server per ssh durch den Tunnel erreichen, beim Namen, von den Geräten, die du zulässt.
lead: Port 22 auf einem Server mit öffentlicher Adresse zieht den ganzen Tag Anmeldeversuche an. Läuft juist auf dem Server und auf deinem Laptop, geht ssh durch den Tunnel, und der Port kann zum Internet hin zu.
---

## Was du bekommst

Dein Laptop erreicht den Server mit `ssh server`, im Netz `home` auch mit
`ssh server.home.juist`, durch den Tunnel. Zum Internet hin ist Port 22 zu:
Niemand außerhalb des Netzes kann auch nur ein Passwort oder einen Schlüssel
probieren. Mit [Zugriffsregeln]({{< relref "docs/access" >}}) erreichen
Port 22 auch durch den Tunnel nur die Geräte, die du auswählst.

Im Beispiel heißt der Server `server`, im Netz `home`.

## Was du brauchst

- Ein Netz, in dem der Laptop ist ([das erste Netz]({{< relref "docs/first-network" >}})).
- Den Server unter Linux oder FreeBSD. Öffne dort 41643/udp, mit
  `sudo ufw allow juist` oder
  `sudo firewall-cmd --permanent --add-service=juist && sudo firewall-cmd --reload`,
  damit sich die Geräte direkt mit ihm verbinden ([Ports]({{< relref "docs/relays" >}})).
- Einen Weg hinein, der kein ssh braucht, etwa die Webkonsole oder das
  Rettungssystem deines Anbieters, falls juist auf dem Server stoppt.

## Einrichten

{{< step on="server" >}}
[Installiere juist]({{< relref "docs/install" >}}) und tritt dem Netz mit
einer [Einladung]({{< relref "docs/invites" >}}) bei.
{{< /step >}}

{{< step on="laptop" >}}
Prüf, ob ssh durch den Tunnel geht, bevor du etwas schließt:

```sh
ssh server
```
{{< /step >}}

{{< step on="server" >}}
Schließ Port 22 zum Internet: Entferne die Regel, die ihn öffnet, etwa mit
`sudo ufw delete allow OpenSSH` oder
`sudo firewall-cmd --permanent --remove-service=ssh && sudo firewall-cmd --reload`,
und in der Firewall deines Anbieters, falls er eine hat. Das Paket lässt den
Verkehr auf `juist0` durch ufw und firewalld, ssh durch den Tunnel geht also
weiter. Lass sshd auf allen Adressen lauschen.
{{< /step >}}

## Darauf achten

- **juist ist jetzt dein Weg hinein.** Stoppt juistd auf dem Server oder
  nimmt das Netz ihn heraus, kommst du nur noch über die Konsole des
  Anbieters hinein. `juist health` auf dem Server sagt vorher, worum du dich
  kümmern musst.
- **Ein Server ohne Frische behält nur Tunnel zu Vouchern.** In einem Netz
  mit Vouchern baut ein Server, der 48 Stunden von keinem gehört hat, den
  Tunnel zu deinem Laptop ab. `juist health` warnt einen Tag vorher
  ([Frische]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)).
- **Jedes Mitglied erreicht Port 22.** Ohne Zugriffsregeln kann sich jedes
  Gerät im Netz anzumelden versuchen. Eine Regel wie
  `pass from laptop to server proto tcp port 22` beschränkt das auf den
  Laptop. Sie gilt für das ganze Netz, und was keine Regel durchlässt, wird
  abgewiesen.
- **Eine von Hand eingerichtete Firewall muss 22 auf `juist0` durchlassen**,
  und dort auch den Log-Abgleich auf TCP 41644
  ([Firewalls]({{< relref "docs/relays" >}}#firewalls)).

## Weiterlesen

- [Namen]({{< relref "docs/names" >}}): wie Geräte `server` und
  `server.home.juist` auflösen
- [Zugriffsregeln]({{< relref "docs/access" >}})
- [Status und Geräte]({{< relref "docs/status" >}}): `juist status` und
  `juist health`

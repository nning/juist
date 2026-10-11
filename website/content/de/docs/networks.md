---
title: Mehrere Netze
linkTitle: Mehrere Netze
description: Ein Gerät in mehrere Netze gleichzeitig bringen und juist mitteilen, welches Netz ein Befehl betrifft.
lead: Ein Gerät kann mehreren Netzen gleichzeitig angehören, etwa einem privaten und einem für die Arbeit. Die Netze laufen nebeneinander, jedes mit eigenem Daemon, eigener Adresse und eigenen Schlüsseln.
---

## Ein juistd pro Netz

Dein Laptop gehört vielleicht zu deinem privaten Netz und zum Netz deines
Teams. Beide haben verschiedene Admins, verschiedene Geräte und verschiedene
Regeln. juist hält sie auf dem Laptop getrennt, indem jedes Netz seinen
eigenen juistd bekommt, den Daemon, der im Hintergrund die Tunnel aufrecht
hält
([So funktioniert juist]({{< relref "docs/how-it-works" >}})).

Das erste Netz läuft in `juistd.service`. Jedes weitere läuft daneben in
einer nummerierten Instanz: `juistd@juist1`, `juistd@juist2` und so weiter.
Jede Instanz hat ihr eigenes Netzwerkgerät (`juist0`, `juist1`, …), ihr
eigenes Zustandsverzeichnis und ihre eigenen Ports.

## Einem zweiten Netz beitreten oder eines anlegen

{{< step on="laptop" as="einem Gerät, das schon in home ist" >}}
Tritt dem anderen Netz mit dem Link aus der Einladung bei, genau wie beim
ersten:

```sh
sudo juist join 'juist:…'
```

Das neue Netz, etwa `work`, läuft dann neben `home`. Willst du stattdessen
ein eigenes Netz anlegen, geht das mit `juist create work` genauso. Rufst du
den Befehl ohne sudo auf, fragt `juist` einmal nach sudo, um den neuen juistd
zu starten.
{{< /step >}}

{{< step on="laptop" >}}
Prüfe beide Netze:

```sh
juist status
juist devices
```

`juist status` zeigt beide Netze nacheinander, jedes unter einer Überschrift
mit seinem juistd. `juist devices` listet die Geräte aller Netze auf.
{{< /step >}}

## Das Netz auswählen

Befehle, die ein einzelnes Netz betreffen, nehmen es als erstes Argument,
entweder mit seinem Namen oder mit dem Namen seines juistd:

```sh
juist devices work                      # über den Namen
juist devices juist1                    # über den juistd
juist invite work                       # bei mehreren Netzen angeben, welches
juist network renumber work 10.7.0.0/24
```

Ist das Gerät nur in einem Netz, kannst du den Namen weglassen.

Dasselbe erreichst du bei jedem Befehl mit `--network NAME` oder mit der
Umgebungsvariable `$JUIST_NETWORK`.

Die Übersichten `status`, `devices`, `network` und `admins` zeigen alle
Netze, wenn du keines angibst. Alle anderen Befehle fragen nicht nach,
welches Netz du meinst, sondern brechen ab und zählen die Netze auf:

```console
$ juist invite
juist: this device is in 2 networks: home (juist0), work (juist1)
hint: name one first: juist invite home [NAME]
```

Hat ein Befehl selbst ein optionales Argument, steht der Name des Netzes
davor. Um ein Gerät namens `home` ins Netz `home` einzuladen, rufst du also
`juist invite home home` auf.

## Überlappende Adressbereiche

Die IPv4-Bereiche zweier Netze dürfen sich überschneiden. Beide laufen
trotzdem auf demselben Gerät, das Netz mit dem höher nummerierten juistd dann
aber nur über IPv6. `juist status` weist darauf hin und schlägt vor, welches
Netz du umnummerieren solltest:

```console
$ juist status
…
warning: no IPv4 on this host: "home" (juist0) holds 198.18.36.2, which "work" claims too (198.18.36.0/22)
hint: renumber one of the two networks: juist network renumber juist1 PREFIX, or the other
```

Sobald eines der beiden Netze
[umnummeriert]({{< relref "docs/network-changes" >}}) ist, funktioniert IPv4
von selbst wieder.

## Ein Admin-Schlüssel pro Netz

Ein Admin-Schlüssel ist der Schlüssel, mit dem ein Admin Änderungen
signiert. Jedes Netz bekommt einen eigenen, etwa `admins/alice@home.key` und
`admins/alice@work.key`. Geht ein Schlüssel verloren oder wird er gestohlen,
ist daher nur ein Netz betroffen. Soll ein neues Netz mit einem Schlüssel
verwaltet werden, den du schon hast, gibst du ihn an:
`juist create lab --admin-key alice@home`. Mehr dazu unter
[Mehrere Admins]({{< relref "docs/admins" >}}).

## Ein Netz verlassen

```sh
juist reset work --force
```

Damit verlässt das Gerät `work`, und der zugehörige juistd wird entfernt.
`home` bleibt mit seinen Schlüsseln unverändert. `--force` ist nötig,
solange `work` das Gerät noch als Mitglied führt. Entferne das Gerät nach
Möglichkeit vorher aus `work` ([Schlüssel]({{< relref "docs/keys" >}})).

## Hinweise

- Auf einem Host laufen höchstens zehn juistd: `juistd.service` und
  `juistd@juist1` bis `juistd@juist9`.
- Die Ports des n-ten juistd sind die des ersten plus 10·n, also 41653/udp
  für `juistd@juist1` und für den Log-Abgleich TCP 41654 auf `juist1`. Die
  Firewall-Profile, die die Pakete installieren, enthalten nur die Ports des
  ersten Netzes. Die der anderen nennt `juist status`
  ([Relays, Ports und Firewalls]({{< relref "docs/relays" >}})).
- Läuft der juistd des zweiten Netzes nicht, startest du ihn mit
  `sudo systemctl enable --now juistd@juist1`. Sein Log zeigt
  `journalctl -u juistd@juist1`.
- Unter FreeBSD stehen die Instanzen der weiteren Netze in der
  rc.conf-Variable `juistd_instances`, und `service juistd start juist1`
  startet eine davon.
- Ein Gerät kann demselben Netz nur einmal angehören. Weil eine Einladung
  nicht verrät, für welches Netz sie gilt, wird ein zweiter Beitritt zum
  selben Netz zunächst angenommen. Der neue juistd lehnt das Netz dann aber ab
  und nennt die Aufnahme, die ein Admin wieder entfernen sollte.
- Ein Gerät in mehreren Netzen leitet seinen Internetverkehr über
  [einen Exit-Node]({{< relref "docs/exit-nodes" >}}) nur eines dieser Netze.
- Alle juistd laufen unter demselben Benutzer `juist`. Wer einen davon
  übernimmt, hat die Geräteschlüssel aller Netze auf dem Host.
- Die Mitglieder eines Netzes können erfahren, welche Adressen dieser Host in
  seinen anderen Netzen hat, und damit, welche Adressbereiche diese Netze
  nutzen.


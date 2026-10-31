---
title: Mehrere Netze
linkTitle: Mehrere Netze
description: Ein Gerät in mehrere Netze gleichzeitig bringen und juist mitteilen, welches Netz ein Befehl betrifft.
lead: Ein Gerät kann mehreren Netzen gleichzeitig angehören, etwa einem privaten und einem für die Arbeit. Die Netze laufen nebeneinander, jedes mit eigenem Daemon, eigener Adresse und eigenen Schlüsseln.
---

## Ein juistd pro Netz

Dein Laptop gehört vielleicht zu deinem privaten Netz und zum Netz deines
Teams, mit verschiedenen Admins, Geräten und Regeln. juist hält sie getrennt,
indem jedes Netz sein eigenes juistd bekommt.

Das erste Netz läuft in `juistd.service`, jedes weitere in einer
nummerierten Instanz: `juistd@juist1`, `juistd@juist2` und so weiter. Jede
Instanz hat ihr eigenes Netzwerkgerät (`juist0`, `juist1`, …), ihr eigenes
Zustandsverzeichnis und eigene Ports und läuft als eigener Benutzer (`juist`,
`juist1`, …), damit das juistd eines Netzes die Schlüssel eines anderen nicht
lesen kann.

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

Dasselbe erreichst du bei jedem Befehl mit `--network NAME`, und bei allen
außer `juist create`, `juist join` und `juist admins new` auch mit der
Umgebungsvariable `$JUIST_NETWORK`.

Befehle, die etwas auflisten, zeigen alle Netze, wenn du keines angibst:
`status`, `health`, `devices`, `network`, `admins`, `names`, `exit`,
`subnet` und `publish`. Alle anderen Befehle fragen nicht nach, welches Netz
du meinst, sondern brechen ab und zählen die Netze auf:

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
aber nur über IPv6. `juist health` weist darauf hin und schlägt vor, welches
Netz du umnummerieren solltest:

```console
$ juist health
home
nothing needs attention

work
warning: no IPv4 on this host: "home" (juist0) holds 198.18.36.2, which "work" claims too (198.18.36.0/22)
hint: renumber one of the two networks: juist network renumber juist1 PREFIX, or the other
```

Sobald eines der beiden Netze
[umnummeriert]({{< relref "docs/network-changes" >}}) ist, funktioniert IPv4
von selbst wieder.

## Ein Admin-Schlüssel pro Netz

Jedes Netz bekommt einen eigenen Admin-Schlüssel, etwa
`admins/alice@home.key` und `admins/alice@work.key`. Ein verlorener Schlüssel
betrifft also nur ein Netz. Soll ein neues Netz mit einem vorhandenen
Schlüssel verwaltet werden, nenn ihn:
`juist create lab --admin-key alice@home`
([Mehrere Admins]({{< relref "docs/admins" >}})).

## Ein Netz verlassen

```sh
juist reset work --force
```

Damit verlässt das Gerät `work`, und der zugehörige juistd wird entfernt.
`home` bleibt mit seinen Schlüsseln unverändert. `--force` ist nötig,
solange `work` das Gerät noch als Mitglied führt. Entferne das Gerät nach
Möglichkeit vorher aus `work` ([Geräte entfernen]({{< relref "docs/remove" >}})).

## Gut zu wissen

- Auf einem Host laufen höchstens zehn juistd: `juistd.service` und
  `juistd@juist1` bis `juistd@juist9`.
- Die Ports des n-ten juistd sind die des ersten plus 10·n: 41653/udp für
  `juistd@juist1` und der Log-Abgleich auf TCP 41654 auf `juist1`. Die
  Firewall-Profile der Pakete enthalten nur die Ports des ersten Netzes; die
  anderen nennt `juist status`
  ([Relays, Ports und Firewalls]({{< relref "docs/relays" >}})).
- Läuft das juistd des zweiten Netzes nicht, starte es mit
  `sudo systemctl enable --now juistd@juist1`. Sein Log zeigt
  `journalctl -u juistd@juist1`. Unter FreeBSD nennt die rc.conf-Variable
  `juistd_instances` die Instanzen, und `service juistd start juist1` startet
  eine.
- Ein Gerät kann einem Netz nur einmal angehören. Eine Einladung verrät
  nicht, für welches Netz sie gilt, also wird ein zweiter Beitritt zum selben
  Netz zunächst angenommen. Das neue juistd lehnt das Netz dann ab und nennt
  die Aufnahme, die ein Admin entfernen sollte.
- Ein Gerät in mehreren Netzen leitet seinen Internetverkehr über den
  [Exit-Node]({{< relref "docs/exit-nodes" >}}) nur eines dieser Netze.
- Die Mitglieder eines Netzes können die Adressen dieses Hosts in seinen
  anderen Netzen erfahren und damit, welche Adressbereiche diese nutzen.


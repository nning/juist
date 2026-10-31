---
title: Namen nur für Mitglieder
linkTitle: Namen nur für Mitglieder
description: Ein veröffentlichter Name mit echtem Zertifikat, den nur Mitglieder des Netzes öffnen können.
lead: Ein Name wie photos.example.org kann wie jeder veröffentlichte Name ein Zertifikat der CA haben und trotzdem nur für Mitglieder deines Netzes erreichbar sein.
status: [Linux, FreeBSD]
---

## So funktioniert es

Der Ingress reicht einen Namen nur für Mitglieder an niemanden weiter außer
an die CA. Sie prüft den Namen per TLS auf 443, wenn sie das Zertifikat
ausstellt oder erneuert. Alle anderen bekommen nichts, und der Ingress
protokolliert `members only`. Der öffentliche DNS-Eintrag zeigt weiter auf
den Ingress, damit die CA ihn erreicht.

Das Gerät, das TLS beendet, nimmt den Namen nur von den Mitgliedern an, für
die er gedacht ist. Es erkennt sie an der Overlay-Adresse, von der ihre
Verbindung kommt. Vom Ingress nimmt es nur die Prüfung der CA an, sodass ein
kompromittierter Ingress nicht weiterkommt.

Du brauchst eine Domain und einen Ingress, wie sie
[Dienste veröffentlichen]({{< relref "docs/publishing" >}}#setting-it-up)
einrichtet.

## Einrichten

{{< step on="dem Gerät eines Admins" >}}
```sh
juist publish add nas photos --members
```

Der Befehl gibt `nas: publishes photos.example.org:443 (members)` aus, und
`juist publish` listet den Namen mit `(members)` auf.
{{< /step >}}

{{< step on="nas" as="dem Ziel" >}}
```sh
juist publish add photos 127.0.0.1:2342 --members
```

juist holt das Zertifikat über den Ingress und beendet TLS hier. `--members`
markiert auch den Dienst selbst als nur für Mitglieder: juist schickt ihm den
Namen nie, solange das Log den Namen als öffentlich führt. Spätere Befehle
behalten die Markierung bis `--members=false`. Ein Service-Mitglied markiert
seine Dienste mit `juistd --serve NAME=ADDR --members`.
{{< /step >}}

## Wer ihn öffnen kann

Ohne [Zugriffsregeln]({{< relref "docs/access" >}}) jedes Mitglied. Mit
Zugriffsregeln nur die Mitglieder, für die eine Regel den Namen freigibt,
etwa `pass from <family> to name photos`. Eine Regel zum Gerät oder zu `any`
gibt den Namen nicht frei.

Mitglieder unter Linux, FreeBSD und Android erreichen den Namen direkt bei
seinem Gerät. Geräte, die die Namen des Netzes über öffentliches DNS
auflösen, erreichen ihn nicht. `juist health` warnt dort vor jedem solchen
Namen, die Android-App ebenso.

## Gut zu wissen

- Der Name braucht einen eigenen Dienst. juist bedient einen Namen nur für
  Mitglieder nicht, wenn ein anderer Name oder etwas Geteiltes auf demselben
  Gerät denselben Dienst ohne Proxy erreicht. Dessen Clients könnten den
  Dienst sonst im Host-Header nach dem geschützten Namen fragen. Namen, die
  juist mit `--http3` als Proxy weiterleitet, zählen nicht. Lass den Dienst
  nur auf 127.0.0.1 lauschen.
- Das Gerät selbst erreicht den Namen nicht über juist. Sonst käme jedes
  Programm darauf hinein. Nutze dort die eigene Adresse des Dienstes.
- Ein Name nur für Mitglieder liegt immer auf 443, per TLS, ohne `--proxy`.
  Ein erneutes `juist publish add nas photos` ohne `--members` lässt ihn
  geschützt; `--members=false` macht ihn öffentlich.
- Der Name steht wie jedes Zertifikat in den öffentlichen Zertifikatslogs
  der CA. Der Name ist nicht geheim, nur was er anbietet.

## Fehlersuche

| Du siehst | Was zu tun ist |
|---|---|
| `juist health`: `warning: not serving NAME, which is for members alone: OTHER reaches its service as it is, …` | OTHER erreicht denselben Dienst per TCP oder ohne Proxy. Gib NAME einen eigenen Dienst. |
| `juist health`: `warning: not serving NAME, its service meant for members alone: the log has the name public` | Um ihn für Mitglieder zu veröffentlichen, führt ein Admin `juist publish add DEVICE NAME --members` aus. Um ihn öffentlich zu machen, führ `juist publish add NAME HOST:PORT --members=false` auf dem Gerät aus. |
| `juist health`: `warning: NAME, for members alone, is not reached from here, …` | Dieses Gerät löst die Namen des Netzes über öffentliches DNS auf, also führt NAME zum Ingress, der ihn ablehnt. Der Rest von `juist health` sagt warum. |

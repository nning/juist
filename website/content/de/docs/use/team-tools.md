---
title: Werkzeuge nur für Mitglieder
linkTitle: Werkzeuge nur für Mitglieder
description: Ein Wiki, ein Dashboard oder ein anderes internes Werkzeug unter einem echten Namen mit echtem Zertifikat betreiben, das nur Mitglieder deines Netzes öffnen können.
lead: Das Wiki des Teams heißt wiki.example.org und hat ein Zertifikat, dem jeder Browser vertraut, auf Laptops wie auf Telefonen. Aus dem Internet ist es nicht zu erreichen, und die Zugriffsregeln legen fest, welche Mitglieder es öffnen dürfen.
---

## Was du bekommst

Ein **Name nur für Mitglieder** hat wie jeder veröffentlichte Name ein
Zertifikat von Let's Encrypt. Browser öffnen ihn also ohne Warnung, und der
Link ist überall derselbe. Erreichen können ihn nur Mitglieder. Sie verbinden
sich durch den Tunnel direkt mit dem Gerät, auf dem das Werkzeug läuft. Dieses
Gerät nimmt den Namen nur von den Mitgliedern an, für die er gedacht ist. Der Ingress reicht den Namen an niemanden weiter außer an die CA, die
ihn beim Ausstellen des Zertifikats prüft.

## Was du brauchst

- Ein Netz mit einer Domain und einem Ingress.
  [Dienste veröffentlichen]({{< relref "docs/publishing" >}}#setting-it-up)
  richtet beides in seinen ersten drei Schritten einmal ein.
- Das Werkzeug auf einem Gerät unter Linux oder FreeBSD, hier `tools`, das
  nur auf `127.0.0.1:3000` lauscht.
- Mitglieder unter Linux, FreeBSD oder Android.

## Einrichten

{{< step on="dem Gerät eines Admins" >}}
Veröffentliche den Namen nur für Mitglieder:

```sh
juist publish add tools wiki --members
```

Die Ausgabe lautet `tools: publishes wiki.example.org:443 (members)`.
{{< /step >}}

{{< step on="tools" as="dem Ziel" >}}
Leg fest, wohin die entschlüsselten Verbindungen gehen, und markiere den
Dienst als nur für Mitglieder, damit juist ihm nie einen öffentlichen Namen
schickt:

```sh
juist publish add wiki 127.0.0.1:3000 --members
```
{{< /step >}}

{{< step on="dem Gerät eines Admins" >}}
Ohne Zugriffsregeln öffnet jedes Mitglied den Namen. Um das einzuschränken,
nenn ihn in einer Regel:

```text
table <team> { laptop, laptop2, phone }

pass from <team> to name wiki
```

und leg die Regeln mit `juist policy set policy.conf` fest. Eine Regel zum
Gerät oder zu `any` öffnet den Namen nicht.
{{< /step >}}

## Darauf achten

- **Die Zugriffsregeln gelten für das ganze Netz.** Sobald es welche gibt,
  wird zwischen allen Geräten abgewiesen, was keine Regel durchlässt, nicht
  nur beim Wiki.
- **Der Name ist kein Geheimnis.** Wie bei jedem Zertifikat steht er in den
  öffentlichen Zertifikatslogs der CA. Was er bereitstellt, bleibt bei den
  Mitgliedern.
- **Das Werkzeug braucht einen eigenen Dienst.** Erreicht ein anderer Name
  oder eine Freigabe auf demselben Gerät denselben Dienst, bedient juist den
  Namen nur für Mitglieder nicht, und `juist health` sagt, warum.
- **`tools` selbst erreicht den Namen nicht über juist.** Öffne das Werkzeug
  dort unter `127.0.0.1:3000`.
- **Ein Mitglied, das die Namen des Netzes nicht auflöst, erreicht ihn
  nicht.** `juist health` warnt auf diesem Mitglied vor dem Namen und sagt,
  warum.

## Weiterlesen

- [Namen nur für Mitglieder]({{< relref "docs/members-only" >}})
- [Zugriffsregeln]({{< relref "docs/access" >}})
- [Namen]({{< relref "docs/names" >}})

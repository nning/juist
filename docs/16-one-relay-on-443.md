# 16 — Every member through one relay on 443

The rules of M22, done ([05-roadmap.md](05-roadmap.md)). A device on a
network that passes TCP to 443 alone has no direct path, so every packet
goes through a relay, and it reaches the relays named on 443 and no other. A
member is sent to at the relay it is homed at, so a member homed at an
unnamed relay is out of the device's reach, with `--https-only` or without
it, though the member reaches the device. Where every relay's port is open,
every device reaches every relay and the question never comes up. Before M22
the answer was a name on 443 for every relay a member may be homed at, set
by hand.

## What it is for

A device in a hotel or a company's network that passes HTTPS alone reaches
every member, and is reached by every member, as long as one relay of the
network is named on 443, and that relay is the ingress's without being set.
No setting on the device is needed but a company's proxy (`--proxy`), and
`--https-only` stays what it is for: no UDP at all, against DPI, and the
proxy.

## Why meeting at the device's relay works

- A DERP server delivers a packet to whichever client holds a connection
  under the destination key, homed there or not; a home is the client's
  notion alone (the pinned derpserver looks the key up among its clients
  and nothing else).
- The device holds a connection to its home, a relay named on 443. Every
  member reaches that relay, and opens a connection to it as soon as it
  sends the device anything, since magicsock sends to a peer's home.
- So both ends meet at the device's home: the member sends there because it
  is the device's home, the device sends there because it is the one relay
  it holds. No relay passes anything to another.
- What it takes is that the member is still connected when the device sends
  first: magicsock closes a connection to a region other than its home once
  nothing was written on it for 60 s (`derpInactiveCleanupTime`), checked
  every 15 s.

## The rules

- **A device is walled** where it has a home and some member relay, not its
  home, went unmeasured in two netchecks in a row without UDP answered (or
  in one, on `--https-only`, for a relay without a name): the netcheck
  without UDP measures every relay by HTTPS, so one it did not measure is
  out of its reach, and one miss may be a far relay past netcheck's time. A
  relay measured, or UDP answered, ends it at once; a report that measured
  nothing changes nothing, and a relay that answered ICMP and not HTTPS
  counts as unmeasured. Where one report left this open, the device asks for another
  10 s later (`conn/walls.go`).
- **STUN servers answering alone are left out.** netcheck measures by
  HTTPS only where no UDP is answered, so where public STUN servers answer
  and no relay's port does, it measures no relay and the device is
  homeless. After two such reports in a row the map leaves the STUN servers
  out, so that the relays are measured by HTTPS, their names on 443 first,
  until the device's link changes; the relays' own STUN ports still tell it its public address
  where they answer. The device stays homeless until a relay is measured,
  and goes homeless after two reports without them that measured nothing,
  as no STUN server is there to be taken for the nearest region; where
  HTTPS reaches none either, with the relays' names first where there are
  any, as with the relays down, it goes homeless at once and the STUN
  servers come back, to be left out again no sooner than 25 s later,
  doubling up to 10 minutes.
- **A relay pinged alone is no home.** A juistd with the right to ping has
  netcheck ping the relays beside HTTPS where UDP is blocked; which relays
  answered ICMP and not HTTPS is read from netcheck's lines, and where
  netcheck chose one for the home, the device is held at the nearest relay
  HTTPS reached, or none, until a report pings none alone
  (`conn/pinged.go`).
- **A device without UDP tries names first.** Where two reports in a row
  without UDP reached no relay, relays' names on 443 come before their own
  ports in the map, which a network passing 443 alone drops at a cost of
  1.5 s each, more than netcheck leaves itself after STUN; a home kept from
  before changes nothing, and one such report alone, as after a link
  change, moves nothing but a report asked 10 s later. A report with UDP
  puts the ports first again.
- **A walled device sends where it can.** A peer homed at a relay it does
  not reach is given its own home as the relay to send to, in the node view
  magicsock takes (`HomeDERP`); magicsock drops a packet to a region its map
  lacks before it tries the route a peer last came by, so this cannot be left
  to it. A peer homed where it reaches is sent to there, as before.
- **A home is announced once measured.** Where a report measured no relay,
  the engine picks a home by its number, which a device announced, and its
  peers sent to it there in vain, as after its restart; a home is announced
  where the last report measured it, or it is the one announced already.
  A peer that says it has no home is sent to at the one it had, for 2
  minutes, as one that restarts is homeless before it takes it again.
- **It says so while undecided too.** A device homed without UDP, whose
  last report missed a relay that one more report has to decide on, says it
  is walled meanwhile: said otherwise, members stop keeping its home open
  and hear the walls that follow only at their next sync, two minutes on.
- **It says so by announcing no address,** open or sealed: a home and no
  address is what peers read as walled, which a device on `--https-only`
  announces already. No field is added, so no schema is raised. Walls
  coming or going are pushed to the members awake alone, at once while
  saving too.
- **Members stay where a walled device is.** A member writes a byte to
  each walled peer's home every 45 s, below magicsock's 60 s idle limit
  checked every 15 s, addressed to a key no client holds, which the relay
  drops: the walled peer receives nothing, and one write serves every
  walled peer homed there. It does not where that home is its own or out
  of its reach, or where its own home has a name on 443, which a walled
  device reaches and sends to itself; and again at once only where a
  walled peer or its home moved. It keeps the connection 2 minutes past the
  last write a walled peer needed: one that restarts says first that it is
  homeless, then not walled, before it is walled at the same home again. A
  member that rests, or saves battery, keeps none: the walled device
  reaches it once it sends, as when it syncs.
- **The announcement reaches them without UDP.** A walled device without
  `--https-only` leaves its announcement at the relays on 443, and looks
  there, in each DHT round it is walled, as far as it would take part in
  the DHT; the public DHT is joined again once it is not. Where the names
  on 443 it holds move, it leaves its announcement there again at once,
  changed or not: a relay that took a new name, or restarted, holds none.
- **The ingress is found by its role's name.** An announcement found
  without a signature, as at a relay's rendezvous, names no relay, so a
  device whose every relay name moved learns no new one there. The ingress
  that relays is therefore taken at `relay.<domain>`, the name its role
  gives it in the log, where it announces none proven, and first while the
  device reaches no relay without UDP, and after that until the ingress
  announces another name, as a name once proven stays so until its server
  says otherwise; its server must say it is that member, as for
  any name (`daemon/relay.go`). A device that reaches no relay at all learns
  a name the ingress moved to only once it reaches a member again.
- **The ingress's relay is named by itself.** On the ingress that relays,
  the one of the lowest identity where several do, the relay takes
  `relay.<domain>` unless `--relay-name` says another name, and the service
  restarts the mesh when that moves; an ingress whose membership expired
  takes none. `juist publish add` refuses the label `relay` while such an
  ingress exists, and `juist grant` warns where it makes the first while
  another holds the name.
- **Health says who is not there.** Where the device's home answers that a
  peer sent to is not connected (`PeerGone`, read from magicsock's line),
  `juist health` names the peers down since then, or since the check that
  found them down began: a warning for one that runs, the reason of no
  answer for one that may be offline, nothing for one known to be.

## The alternative: relays that forward

Should meeting at the device's relay fall short, as for a member that
cannot keep a connection open, relays forward for one another instead:
one hop, between members of the relay role alone, admitted by identity and
role at both ends, for packets whose source and destination are both
members'. The pinned derpserver has the parts (`SetMeshKey`,
`AddPacketForwarder`, `RunWatchConnectionLoop`, `ForwardPacket`) and never
forwards a forwarded packet again, but its mesh key is one shared secret
whose holder skips admission, gets no rate limit and may close any client,
so no such key may leave the process that drew it: each relay would be the
one mesh client of its own server, and relays would talk over a link of
juist's own. That adds n·(n−1)/2 links, a forwarding relay that sees pairs
not its own, and an admission whose failure is silent, which is why it is
not the lead.

## The threat model

What changes is in [02-threat-model.md](02-threat-model.md), weaknesses 5
and 15. The change is audit scope (M32).

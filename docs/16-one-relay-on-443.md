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
  nothing changes nothing, and a relay without a name pinged by ICMP
  counts as unmeasured. Where one report left this open, the device asks for another
  10 s later (`conn/walls.go`).
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
- **It says so by announcing no address,** open or sealed: a home and no
  address is what peers read as walled, which a device on `--https-only`
  announces already. No field is added, so no schema is raised. Walls
  coming or going are pushed to the members awake alone, at once while
  saving too.
- **Members stay where a walled device is.** A member sends a quiet disco
  ping to each walled peer at its home every 45 s, below magicsock's 60 s
  idle limit checked every 15 s, unless that home is its own or out of its
  reach, and again at once only where a walled peer or its home moved. A
  member that rests, or saves battery, keeps none: the walled device
  reaches it once it sends, as when it syncs.
- **The announcement reaches them without UDP.** A walled device without
  `--https-only` leaves its announcement at the relays on 443, and looks
  there, in each DHT round it is walled, as far as it would take part in
  the DHT; the public DHT is joined again once it is not.
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

## Still open

- **Homes reached by TCP alone.** netcheck measures by HTTPS only where no
  UDP probe is answered, so on a network that passes a public STUN server
  but no relay's port, no relay is measured and the device is homeless.
  Measuring the relays by HTTPS where their STUN goes unanswered is not part
  of M22.
- **The first meeting after a restart.** A walled device is walled within
  20 s of its juistd starting and leaves its announcement at its relay at
  once, which pushes it on; yet in two lab runs of nine, hotel reached lx
  only after 1m48s and 2m31s, where the others took 21 to 37 s. The lab now
  logs how lx sees hotel and when fb heard of it, which is what the next
  such run has to answer.
- **A home pinged alone.** A juistd running as root pings relays by ICMP
  where UDP is blocked, and netcheck may take the nearest relay it pinged,
  without a name and out of its reach by TCP, for its home, as before M22;
  the packages run juistd without the right to ping.
- **The last name gone.** A walled device whose relays on 443 all lose
  their names, or move, learns nothing new: it reaches no member to hear
  of the names that replace them.
- **Peers kept open for nothing.** A peer on `--https-only` that reaches
  every relay, or one whose addresses are withheld from this device, reads
  as walled too, and costs each member a connection and a ping every 45 s.
- **A walled phone is pinged.** The keepalive is a ping to the walled device
  itself, so a phone walled in a hotel's Wi-Fi answers every member every
  45 s, which M21's budgets do not cover; a write that reaches the relay
  alone would spare it, and magicsock exports none.

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
and 15. The change is audit scope (M26).

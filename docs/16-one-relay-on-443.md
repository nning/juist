# 16 — Every member through one relay on 443

The plan of M22 ([05-roadmap.md](05-roadmap.md)). A device on a network that
passes TCP to 443 alone has no direct path, so every packet goes through a
relay, and it reaches the relays named on 443 and no other. A member is
sent to at the relay it is homed at, so a member homed at an unnamed relay
is out of the device's reach, with `--https-only` or without it, though the
member reaches the device. Where every relay's port is open, every device
reaches every relay and the question never comes up. Today the answer is a
name on 443 for every relay a member may be homed at, set by hand.

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

## The rules (lead option)

- **A device sends where it can.** A peer whose home this device does not
  reach, or which its relay map does not hold (an unnamed one on
  `--https-only`), is given this device's own home as the relay to send to
  (`conn/peers.go`, where a peer's `HomeDERP` is set). A peer whose home
  it reaches is sent to there, as now.
- **Members stay where such a device is.** A member keeps its connection to
  the home of each peer that reaches named relays alone, by writing on it
  more often than magicsock's idle limit, as long as the peer's announcement
  says so and the access policy lets the pair talk. A member that rests, as
  a phone, keeps none: the device reaches it when it next syncs.
- **The device's announcement says so.** Peers learn that a device reaches
  named relays alone, and where its home is, from its announcement; one on
  HTTPS alone announces no address already.
- **The announcement reaches them without UDP.** A device that reaches no
  DHT leaves its announcement at the relays on 443, as a device on HTTPS
  alone does, so that a member learns its new home without a tunnel to it
  first.
- **The ingress's relay is named by itself.** On an ingress host the relay
  takes `relay.<domain>` on 443 unless `--relay-name` says another name,
  so the domain's wildcard record is all a network needs. A published name
  `relay` is refused while it is the relay's.
- **Status says who is not there.** Where the device's relay answers that a
  peer is not connected (`PeerGone`), `juist health` says which peer the
  device cannot reach first.

## Open decisions

- **The keepalive.** What is written, and how often: a disco ping to the
  device on its home every 45 s, or WireGuard's persistent keepalive for
  that peer, which juist sets for none today; what it costs a laptop in a
  network of many such devices.
- **The announcement.** Whether "reaches named relays alone" is a field of
  its own, which raises `types.CurrentSchema` and so wants a new Android
  app, or is read from an announcement without addresses, which a device
  measured into it without `--https-only` would then have to send.
- **Detecting it without the setting.** When a device without
  `--https-only` counts as reaching named relays alone: after a netcheck
  that measured no unnamed relay, and how it leaves that state again.
- **Homes reached by TCP alone.** netcheck measures by HTTPS only where no
  UDP probe is answered, so on a network that passes a public STUN server
  but no relay's port, no relay is measured and the device is homeless.
  Whether juist measures the relays by HTTPS where their STUN goes
  unanswered.
- **Several ingresses.** Which one's relay takes `relay.<domain>`, or one
  name each.

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

What changes in [02-threat-model.md](02-threat-model.md), to be written
there when M22 is done:

- **Nothing about relays' trust.** A relay still sees node keys and
  WireGuard ciphertext alone; it admits members as now, and no relay is
  given a right over another.
- **Availability and metadata concentrate (weakness 5).** Every pair of a
  device that reaches named relays alone goes through its home, which sees
  the timing and volume of all of them, and can stop all of them; today
  they are spread over the peers' homes.
- **Members say they are online there.** Each member keeps a connection to
  such a device's home, so that relay sees which members run while the
  device is there, as it sees its own clients now.
- **An announcement left at the relays** without `--https-only` tells them
  which members the device looks for, as weakness 5 says of a device on
  HTTPS alone.
- **Strangers crowd members out (weakness 15)** of the one relay that now
  carries every pair of such a device.

The change is audit scope (M26).

---
title: Access policy
linkTitle: Access policy
description: Say which device may open what on which, which exit nodes and subnets each may use, and keep the rest of the network apart.
lead: Without an access policy, every device may open anything on every other. With one, devices open on each other only what it passes, and everything else is refused.
---

## What it is

The access policy is a list of rules that the network's log holds, the signed
list of every change ([How juist works]({{< relref "docs/how-it-works" >}})).
An admin, a person whose key approves changes, sets it, and every device
enforces it from then on.

A rule passes connections:

```text
pass from laptop to nas proto tcp port 445
```

lets laptop open connections to port 445 on nas, and nas answer them. It
does not let nas open anything on laptop. What no rule passes is refused.
There are no rules that block, and their order means nothing.

The policy also decides who may use an [exit node]({{< relref "docs/exit-nodes" >}})
or reach a [subnet]({{< relref "docs/subnets" >}}). Roles still decide who
may serve: `juist grant vps exit` makes vps an exit node, and the policy says
which devices may send their internet traffic through it.

## Setting a policy

Say the network has two laptops, a phone, a NAS at home, and a VPS that is
its exit node and relay. The laptops should reach the NAS by ssh and SMB, and
ping it, and the phone its photos on port 443. The laptops go online through
the VPS, and only laptop may log in to it.

{{< step on="an admin's device" >}}
Write the policy to a file, `policy.conf`:

```text
table <laptops> { laptop, laptop2 }

pass from <laptops> to nas proto icmp proto tcp port { 22, 445 }
pass from phone to nas proto tcp port 443
pass from <laptops> to internet via vps
pass from laptop to vps proto tcp port 22

test pass from laptop2 to nas proto tcp port 445
test block from nas to laptop
test block from phone to laptop
```

The `test` lines say what the policy must pass and what it must refuse.
They stay in the policy, and it is not set while one fails.
{{< /step >}}

{{< step on="an admin's device" >}}
Check it against the network, then set it:

```console
$ juist policy check policy.conf
policy.conf: passes its 3 tests
$ juist policy set policy.conf
devices then open on each other only what the policy passes; set it? [y/N] y
access policy set: 4 rules
```

Only the first policy is asked about; `--yes` answers for a script. Where a
change needs more than one admin, it waits for the others as
`policy.rec` ([Several admins]({{< relref "docs/admins" >}})).
{{< /step >}}

{{< step on="laptop2" >}}
`juist devices` now lists laptop2, nas and vps, and ends with:

```console
hint: 2 more devices the access policy keeps apart from this one: juist devices --all
```

No rule joins laptop2 with laptop or the phone, so it keeps no tunnel to either.
After `juist exit use vps`, laptop2 goes online through vps, and so does its
DNS where systemd-resolved runs.
{{< /step >}}

`juist policy` prints the network's policy. `juist policy edit` opens it in
`$VISUAL` or `$EDITOR`, or vi where neither is set, and sets what you save
once it reads and passes its tests. `juist policy off` withdraws it: every device
may then open anything on every other again.

## The language

The language is the filter part of pf, the BSD packet filter:

- `table <name> { laptop, phone, <other> }` names a group of devices and
  tables.
- `service web = proto tcp port { 80, 443 }` names ports.
- `pass from SOURCE to DESTINATION`, then `proto`, `port` and `service` as
  needed.

A source is a device, a `<table>`, `any` for every device, or several of
them in braces. A destination is one of those, or:

- `internet`, through every exit node, or `internet via vps` through one
  device or table;
- an address or prefix behind a subnet router, such as `192.168.1.0/24` or
  `192.168.1.20`.

`proto` takes `tcp`, `udp`, `icmp` or a list in braces, and `port` takes a
port, a range such as `8000:8080`, or a list. A rule can hold several `proto`
clauses. A rule without `proto`, `port` or `service` passes everything. Ping
needs `proto icmp`, or a rule without a protocol.

A test reads `test pass` or `test block`, from one device to one device,
`internet via` one exit node, or one address. With a protocol and a port it
asks for that one connection; with a protocol alone, for any port of it;
with neither, whether anything passes at all. A rule's `proto tcp`, by
contrast, passes every TCP port.

A device named like a keyword, such as `test`, goes in double quotes:
`"test"`. A rule goes on past the end of a line inside braces, or after a
`\` as in pf. The policy has no comments, and `#` is an error: the log keeps
the policy's rules, not its text, so the reason for a rule belongs in the
commit message.

`juist policy fmt` prints a file in the policy's own form, as
`juist policy` prints it: lists sorted, and tables, services, rules and tests
each in a block. It needs no network.

## What it means

- Each device enforces the policy on what reaches it, and keeps track of the
  connections it passed, so answers get back. A device that ignores the
  policy still gets nothing through. Devices also drop what they may not
  open themselves.
- An exit node forwards for a device only what the policy passes it. A
  device the policy lets use an exit node may also ask its DNS. A subnet
  router does the same for its subnet.
- A [service member]({{< relref "docs/publishing" >}}) opens nothing,
  whatever the policy says. An ingress reaches what is published on a
  device, whatever the policy says.
- Two devices that no rule joins, either way, are not peers: they keep no
  tunnel, and neither learns where the other is reached. `juist devices`,
  `juist status` and the names `DEVICE.NETWORK.juist` show a device itself
  and its peers.
- Relays and vouchers reach every device for juist's own traffic, since
  they carry the log. In a network with neither, every two devices keep a
  tunnel for juist's own traffic alone.
- A device whose view of the network is stale keeps tunnels only to
  vouchers, as without a policy, and passes nothing but juist's own traffic
  through them ([freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)).

## Why a connection does not get through

What the policy refuses is dropped without an answer, so a connection to it
hangs until it times out; a device the policy keeps apart from this one does
not resolve as `DEVICE.NETWORK.juist` at all. `juist policy test` says what
the policy makes of a connection, and which rule passes it:

```console
$ juist policy test from laptop to nas proto tcp port 445
passes: pass from <laptops> to nas proto icmp proto tcp port { 22, 445 }
$ juist policy test from laptop to nas proto tcp port 8080
refused: no rule passes it
hint: laptop may open on nas: proto icmp proto tcp port { 22, 445 }
```

It takes what a `test` line takes, and exits 1 where no rule passes.

## What it does not hide

The log stays whole on every device: every device's name, keys and address
in the network, the roles, and the policy itself. Any member can read the
whole policy with `juist policy`. The policy keeps devices from connecting,
and keeps where a device is reached from those that are not its peers. It
does not keep secret which devices the network has.

## Keeping the policy in git {#git}

The file can live in a repository and be changed by merge request:

- CI runs `juist policy fmt -l policy.conf`, which lists the file and fails
  where it is not in the policy's own form. `juist policy fmt -w` rewrites
  it.
- `juist policy check policy.conf` reads it against the network and runs its
  tests. It needs the network's log, so it runs on a device of the network.
- After the merge, an admin runs `juist policy set policy.conf`. Where the
  change needs more admins, `policy.rec` goes to them, and
  `juist approve policy.rec` shows the change as a diff against the current
  policy, with any test it fails.
- `juist policy diff policy.conf` prints both in the policy's own form, a
  line only the network's policy has after `- `, one only the file has after
  `+ `, and the lines both have indented, and exits 1 where they differ. It
  finds a change made with `juist policy edit` and not in git. A device
  removed or renamed since makes it fail on the file's line naming it.

Give no CI job an admin key that reaches the quorum alone. Whoever can push
to the repository would then change the network.

## Good to know

- `juist policy set` refuses an empty file; `juist policy off` withdraws
  the policy. `pass from any to any` lets every device open anything on
  every other, but not use exit nodes or subnets.
- `juist invite` under a policy prints
  `hint: the access policy passes phone nothing until it names it: juist policy edit`.
- `juist policy check` and `set` warn of what cannot work as written, or
  leaves something unused: an exit node without the role, a prefix no subnet
  router routes, a device's own address where its name belongs, a service
  member or an ingress as a source, a device in no rule, an exit node or a
  subnet router no rule uses, a table or service no rule uses.
- `juist policy set -` reads the policy from standard input.
- `juist log` lists each change of the policy, and who approved it.
- A removed device drops out of every rule, and a rule or test left without
  it goes; `juist remove` says what the policy loses.
- `juist devices --all` lists the devices the policy keeps apart from this
  one too, as an admin needs to rename or remove them.

## If something goes wrong

| You see | What to do |
|---|---|
| `juist: the network predates access policies` | update juist on every device, then run `juist log upgrade` |
| `juist: policy.conf:3: no device "nobody" in "home"` | correct the name; `juist devices --all` lists them, and `juist log` says whether one was renamed or removed |
| `policy.conf:9: fails: test block from nas to laptop: pass from any to any passes it` | change the rule that passes it, or the test |
| `juist: policy.conf:1: a policy has no comments: …` | remove the comment; say why in the commit message |
| `juist: …: "test" is a word of the policy's; the device goes in double quotes: "test"` | put the device's name in double quotes |
| ssh or SMB hangs, then times out | `juist policy test from laptop to nas proto tcp port 22` says whether the policy passes it |
| `nas.home.juist` does not resolve | no rule joins this device and nas; `juist policy test from laptop to nas` |
| ping fails, ssh works | add `proto icmp` to the rule |
| `juist status`: `Exit node` says `vps, internet refused: the access policy does not let this device use it` | add a rule `pass from … to internet via vps` |
| `juist subnet`: `not in use: the access policy passes none of it to this device` | add a rule for an address or prefix in the subnet |

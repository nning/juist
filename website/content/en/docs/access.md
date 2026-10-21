---
title: Access policy
linkTitle: Access policy
description: Decide which devices may connect to which and on what ports, which exit nodes and subnets each may use, and keep the rest of the network apart.
lead: Without an access policy, every device may open any connection to every other. With one, devices may open only the connections it passes, and everything else is refused.
---

## How rules work

The access policy is a set of rules in the network's
[membership log]({{< relref "docs/how-it-works" >}}#the-membership-log). An
admin sets it, like any other change, and from then on every device enforces
it.

Each rule passes connections. This one:

```text
pass from laptop to nas proto tcp port 445
```

lets laptop open connections to port 445 on nas, and lets nas answer them.
It does not let nas open anything on laptop. Anything no rule passes is
refused. There are no rules that block, and the order of the rules does not
matter.

The policy also decides who may use an [exit node]({{< relref "docs/exit-nodes" >}})
or reach a [subnet]({{< relref "docs/subnets" >}}). Who may serve as one is
still decided by roles: `juist grant vps exit` makes vps an exit node, and
the policy says which devices may send their internet traffic through it.

## Setting a policy

Say the network has two laptops, a phone, a NAS at home, and a VPS that is
its exit node and relay. Both laptops should be able to reach the NAS by ssh
and SMB and to ping it, and the phone should reach its photos on port 443.
The laptops go online through the VPS, and only laptop may log in to it.

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
They are saved with the policy, and the policy is not set while any of them
fails.
{{< /step >}}

{{< step on="an admin's device" >}}
Check it against the network, then set it:

```console
$ juist policy check policy.conf
policy.conf: passes its 3 tests
$ juist policy set policy.conf
anything the policy does not pass is then refused; set it? [y/N] y
access policy set: 4 rules
```

juist asks only before setting the first policy; in a script, `--yes`
answers for you. If a change needs more than one admin, it waits for the
others as `policy.rec` ([Several admins]({{< relref "docs/admins" >}})).
{{< /step >}}

{{< step on="laptop2" >}}
`juist devices` now lists laptop2, nas and vps, and ends with:

```console
hint: 2 more devices the access policy keeps apart from this one: juist devices --all
```

No rule connects laptop2 with laptop or the phone, so it keeps no tunnel to
either. After `juist exit use vps`, laptop2 goes online through vps, and its DNS
goes through vps too.
{{< /step >}}

`juist policy` prints the network's policy. `juist policy edit` opens it in
`$VISUAL` or `$EDITOR`, or in vi if neither is set. When you save, it sets
the new policy, provided it parses and passes its tests. `juist policy off`
withdraws the policy, and every device may again open any connection to
every other.

## The rule language

Policies are written in the language of pf's filter rules (pf is the BSD
packet filter):

- `table <name> { laptop, phone, <other> }` names a group of devices and
  tables.
- `service web = proto tcp port { 80, 443 }` names a set of ports.
- `pass from SOURCE to DESTINATION`, followed by `proto`, `port` and
  `service` as needed.

A source is a device, a `<table>`, `any` for every device, or several of
these in braces. A destination is any of those, or:

- `internet`, through any exit node, or `internet via vps`, through one
  device or table;
- an address or prefix behind a subnet router, such as `192.168.1.0/24` or
  `192.168.1.20`;
- `name photos`, a [members-only name]({{< relref "docs/publishing" >}}#names-for-members-alone),
  given by its label under the network's domain, or `name @` for the domain
  itself. The rule lets its sources open port 443, over TCP and UDP, on the
  device that publishes the name and terminates its TLS, and only for that
  name. A members-only name needs such a rule: a rule to its device, or to
  `any`, opens the port but not the name. A rule with a `name` has no other
  destination and no port. A rule naming a public name published by TLS opens that name's port on its device
  to the sources in the same way. If another device publishes the name
  later, the rule opens that device instead.

`proto` takes `tcp`, `udp`, `icmp` or a list in braces. `port` takes a
port, a range such as `8000:8080`, or a list. A rule can have several
`proto` clauses. A rule without `proto`, `port` or `service` passes
everything. Ping needs `proto icmp`, or a rule without a protocol.

A test starts with `test pass` or `test block`. It checks a connection from
one device to a single destination: one device, `internet via` one exit
node, one address, or one name, given without a port. With a protocol and a
port, the test checks exactly that connection. With only a protocol, it
checks any port of that protocol, and with neither, whether anything passes
at all. In a rule, by contrast, `proto tcp` passes every TCP port.

A device whose name is a keyword, such as `test`, goes in double quotes:
`"test"`. A rule continues onto the next line inside braces, or after a
`\`, as in pf. The policy has no comments, and `#` is an error: the log
stores the policy's rules, not its text, so the reason for a rule belongs in
the commit message.

`juist policy fmt` prints a file in standard form, the way `juist policy`
prints the policy: lists sorted, and tables, services, rules and tests each
in their own block. It does not need a network.

## How devices enforce it

- Each device enforces the policy on the traffic it receives, and tracks the
  connections it passed so that replies get back. Even a device that ignores
  the policy gets nothing through. Devices also drop outgoing traffic they
  may not open themselves.
- An exit node forwards for a device only what the policy passes. A device
  the policy lets use an exit node may also use its DNS. A subnet router
  does the same for its subnet.
- A [service member]({{< relref "docs/publishing" >}}) opens nothing,
  whatever the policy says. An ingress reaches what is published on a
  device, regardless of the policy.
- Two devices that no rule connects, in either direction, are not peers:
  they keep no tunnel, and neither learns where the other can be reached.
  `juist devices`, `juist status` and the names `DEVICE.NETWORK.juist` show
  only the device itself and its peers.
- Relays and vouchers reach every device for juist's own traffic, since
  they carry the log. In a network with neither, every pair of devices keeps
  a tunnel, but only for juist's own traffic.
- A device whose view of the network is stale keeps tunnels only to
  vouchers, as it would without a policy, and passes nothing but juist's own
  traffic through them ([freshness]({{< relref "docs/how-it-works" >}}#freshness-and-vouchers)).

## Why a connection does not get through

Anything the policy refuses is dropped without a reply, so the connection
hangs until it times out. A device the policy keeps apart from this one does
not resolve as `DEVICE.NETWORK.juist` at all. `juist policy test` says what
the policy does with a connection, and which rule passes it:

```console
$ juist policy test from laptop to nas proto tcp port 445
passes: pass from <laptops> to nas proto icmp proto tcp port { 22, 445 }
$ juist policy test from laptop to nas proto tcp port 8080
refused: no rule passes it
hint: laptop may open on nas: proto icmp proto tcp port { 22, 445 }
```

It takes the same arguments as a `test` line, and exits with status 1 if no
rule passes the connection.

## What the policy does not hide

Every device holds the whole log: every device's name, keys and network
address, the roles, and the policy itself. Any member can read the whole
policy with `juist policy`. The policy stops devices from connecting, and
hides where a device can be reached from devices that are not its peers. It
does not hide which devices the network has.

## Keeping the policy in git {#git}

The file can live in a repository and be changed by merge request:

- CI runs `juist policy fmt -l policy.conf`, which lists the file and fails
  if it is not in standard form. `juist policy fmt -w` rewrites it.
- `juist policy check policy.conf` checks it against the network and runs
  its tests. It needs the network's log, so it has to run on a device in the
  network.
- After the merge, an admin runs `juist policy set policy.conf`. If the
  change needs more admins, `policy.rec` goes to them, and
  `juist approve policy.rec` shows the change as a diff against the current
  policy, along with any test it fails.
- `juist policy diff policy.conf` prints both in standard form. Lines only
  the network's policy has start with `- `, lines only the file has start
  with `+ `, and lines both have are indented. It exits with status 1 if
  they differ, so it catches a change made with `juist policy edit` that
  never went into git. If a device named in the file has since been removed
  or renamed, it fails at the line that names it.

Never give a CI job an admin key that reaches the quorum on its own, or
anyone who can push to the repository could change the network.

## Notes

- `juist policy set` refuses an empty file; to withdraw the policy, use
  `juist policy off`. `pass from any to any` lets every device open anything
  on every other, but not use exit nodes, subnets or members-only names.
- Under a policy, `juist invite` prints
  `hint: the access policy passes phone nothing until it names it: juist policy edit`.
- `juist policy check` and `set` warn about anything that cannot work as
  written or leaves something unused: an exit node without the exit role, a
  prefix no subnet router routes, a device's address where its name belongs,
  a service member or an ingress as a source, a device no rule names, an
  exit node or subnet router no rule uses, and a table or service no rule
  uses.
- `juist policy set -` reads the policy from standard input.
- `juist log` lists every change to the policy and who approved it;
  `juist log show N` shows one as a diff.
- A removed device drops out of every rule. A rule left without a source or
  a destination is dropped, and so is any test that names the device.
  `juist remove` says what the policy loses.
- `juist devices --all` also lists the devices the policy keeps apart from
  this one, which an admin needs in order to rename or remove them.

## Troubleshooting

| You see | What to do |
|---|---|
| `juist: policy.conf:3: no device "nobody" in "home"` | correct the name; `juist devices --all` lists the devices, and `juist log` says whether one was renamed or removed |
| `policy.conf:9: fails: test block from nas to laptop: pass from any to any passes it` | change the rule that passes it, or the test |
| `juist: policy.conf:1: a policy has no comments: …` | remove the comment and give the reason in the commit message |
| `juist: …: "test" is a word of the policy's; the device goes in double quotes: "test"` | put the device's name in double quotes |
| ssh or SMB hangs, then times out | `juist policy test from laptop to nas proto tcp port 22` says whether the policy passes it |
| `nas.home.juist` does not resolve | no rule connects this device and nas; check with `juist policy test from laptop to nas` |
| ping fails, ssh works | add `proto icmp` to the rule |
| `juist status`: `Exit node` says `vps, internet refused: the access policy does not let this device use it` | add a rule `pass from … to internet via vps` |
| `juist subnet`: `not in use: the access policy passes none of it to this device` | add a rule for an address or prefix in the subnet |

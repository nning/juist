package io.juist.app

import io.juist.app.core.Alarm
import io.juist.app.core.ExitView
import io.juist.app.core.FreshState
import io.juist.app.core.Freshness
import io.juist.app.core.Member
import io.juist.app.core.NetworkView
import io.juist.app.core.Reach
import io.juist.app.core.Severity
import io.juist.app.core.State
import io.juist.app.core.Tunnels

/** The moment every screenshot is taken at, in Unix seconds. */
const val NOW = 1_790_000_000L

/** A phone in a network of six, with a member in each state a reach can be in. */
val sampleView = NetworkView(
    state = State.Connected,
    network = "home",
    self = Member(
        identity = "nid:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", name = "pixel-8",
        v4 = "198.18.36.5", v6 = "fd4c:8a21:e3f:e83:5a7d:f12c:9b46:d371", reach = Reach.Self,
    ),
    members = listOf(
        Member("nid:AgAA", "laptop", "198.18.36.1", "fd4c:8a21:e3f:5b1a:9d02:c4e7:31f8:a6b0", listOf("admin"), reach = Reach.Direct, heard = NOW - 300),
        Member("nid:AwAA", "nas", "198.18.36.2", "fd4c:8a21:e3f:77c0:1e4b:a923:6d05:f18e", reach = Reach.Direct, heard = NOW - 900),
        Member("nid:BAAA", "vps", "198.18.36.3", "fd4c:8a21:e3f:c2d9:84f1:3b6a:e057:29dc", listOf("admin", "relay-capable"), reach = Reach.Relay, heard = NOW - 60),
        Member("nid:BQAA", "desktop", "198.18.36.6", "fd4c:8a21:e3f:1d2e:3f40:5a6b:7c8d:9e0f", reach = Reach.Sought, since = NOW - 400),
        Member("nid:BgAA", "tablet", "198.18.36.7", "fd4c:8a21:e3f:aa01:bb02:cc03:dd04:ee05", reach = Reach.Absent, heard = NOW - 3 * 3600),
        Member("nid:BwAA", "printer", "198.18.36.8", "fd4c:8a21:e3f:1111:2222:3333:4444:5555", reach = Reach.Silent),
    ),
    fresh = Freshness(FreshState.Fresh, since = NOW - 12 * 60, until = NOW + 47 * 3600, vouching = 1, vouchers = 1),
    tunnels = Tunnels(live = 3, total = 5, checked = NOW - 20),
    alarms = listOf(
        Alarm("seeking", Severity.Info, names = listOf("desktop")),
        Alarm("silent", Severity.Info, names = listOf("printer"), count = 1),
    ),
    updated = NOW - 120,
)

val limitedView = sampleView.copy(
    state = State.Limited,
    fresh = Freshness(FreshState.Stale, vouchers = 2, vouching = 0),
    alarms = listOf(Alarm("noRelay", Severity.Warn)),
)

val forkedView = sampleView.copy(
    state = State.Disconnected,
    alarms = listOf(Alarm("fork", Severity.Alarm, text = "two changes of epoch 7 both carry a quorum")),
)

/** The phone's internet through vps, the network's one exit node beside nas. */
val exitView = sampleView.copy(
    exit = ExitView(
        node = "nid:BAAA", name = "vps", dns = true,
        offering = listOf(sampleView.members[2], sampleView.members[1]),
    ),
)

val exitRefusedView = exitView.copy(
    exit = exitView.exit!!.copy(dns = false, refused = "vps no longer serves as an exit node"),
    alarms = emptyList(),
)

val removedView = NetworkView(state = State.Removed, network = "home", self = sampleView.self)

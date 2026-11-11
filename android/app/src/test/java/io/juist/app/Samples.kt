package io.juist.app

import io.juist.app.core.Alarm
import io.juist.app.core.Change
import io.juist.app.core.Details
import io.juist.app.core.Diagnosis
import io.juist.app.core.DnsDiagnosis
import io.juist.app.core.Lookup
import io.juist.app.core.SubnetRoute
import io.juist.app.core.ExitView
import io.juist.app.core.FreshState
import io.juist.app.core.Freshness
import io.juist.app.core.Member
import io.juist.app.core.NamesView
import io.juist.app.core.NetworkView
import io.juist.app.core.PhoneSettings
import io.juist.app.core.PublicName
import io.juist.app.core.Reach
import io.juist.app.core.Severity
import io.juist.app.core.State
import io.juist.app.core.Tunnels
import io.juist.app.core.Underlay

/** The moment every screenshot is taken at, in Unix seconds. */
const val NOW = 1_790_000_000L

/** A phone in a network of six, with a member in each state a reach can be in. */
val sampleView = NetworkView(
    state = State.Connected,
    network = "home",
    self = Member(
        identity = "nid:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", name = "pixel-8",
        v4 = "198.18.36.5", v6 = "fd4c:8a21:e3f:e83:5a7d:f12c:9b46:d371", reach = Reach.Self, dns = "pixel-8.home.juist",
    ),
    members = listOf(
        Member("nid:AgAA", "laptop", "198.18.36.1", "fd4c:8a21:e3f:5b1a:9d02:c4e7:31f8:a6b0", listOf("admin"), reach = Reach.Direct, heard = NOW - 300, dns = "laptop.home.juist"),
        Member("nid:AwAA", "nas", "198.18.36.2", "fd4c:8a21:e3f:77c0:1e4b:a923:6d05:f18e", reach = Reach.Direct, heard = NOW - 900, dns = "nas.home.juist"),
        Member("nid:BAAA", "vps", "198.18.36.3", "fd4c:8a21:e3f:c2d9:84f1:3b6a:e057:29dc", listOf("admin", "relay-capable"), reach = Reach.Relay, heard = NOW - 60, dns = "vps.home.juist"),
        Member("nid:BQAA", "desktop", "198.18.36.6", "fd4c:8a21:e3f:1d2e:3f40:5a6b:7c8d:9e0f", reach = Reach.Sought, since = NOW - 400, dns = "desktop.home.juist"),
        Member("nid:BgAA", "tablet", "198.18.36.7", "fd4c:8a21:e3f:aa01:bb02:cc03:dd04:ee05", reach = Reach.Absent, heard = NOW - 3 * 3600, dns = "tablet.home.juist"),
        Member("nid:BwAA", "printer", "198.18.36.8", "fd4c:8a21:e3f:1111:2222:3333:4444:5555", reach = Reach.Silent, dns = "printer.home.juist"),
    ),
    fresh = Freshness(FreshState.Fresh, since = NOW - 12 * 60, until = NOW + 47 * 3600, vouching = 1, vouchers = 1),
    tunnels = Tunnels(live = 3, total = 5, checked = NOW - 20),
    names = NamesView(domain = "home.juist", own = listOf("pixel-8.home.juist"), resolved = true),
    alarms = listOf(
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

/** Private DNS sends the phone's lookups past juist, so a name for members alone is out of reach. */
val privateDnsView = sampleView.copy(
    names = sampleView.names!!.copy(resolved = false),
    alarms = listOf(
        Alarm("privateDns", Severity.Warn, names = listOf("dns.google")),
        Alarm("forMembers", Severity.Warn, names = listOf("wiki.example.org")),
    ),
)

val removedView = NetworkView(state = State.Removed, network = "home", self = sampleView.self)

/** nas, publishing a wiki for members alone and a game server, and routing the home LAN. */
val servicesMember = sampleView.members[1].copy(
    published = listOf("wiki.example.org", "photos.example.org", "game.example.org:25565"),
    membersOnly = listOf("wiki.example.org"),
    subnets = listOf("192.168.178.0/24"),
    build = 22,
)

/** What juist status says beyond the state, with a subnet in use and one the LAN covers. */
val detailsView = sampleView.copy(
    settings = PhoneSettings(publicNames = true),
    names = sampleView.names!!.copy(public = listOf(PublicName("blog.example.org", "vps"))),
    details = Details(
        schema = 22, appSchema = 22, epoch = 7, head = "3O72DZHV3GMB", relays = 1, installed = 1, home = "vps",
        underlay = Underlay(udp = true, ipv4 = true, ipv6 = true, mapping = true, offered = listOf("UPnP"), mapped = "203.0.113.7:41641"),
        subnets = listOf(
            SubnetRoute("192.168.178.0/24", "nas", inUse = true),
            SubnetRoute("10.20.0.0/16", "vps", why = "this device reaches it by a route of its own"),
        ),
    ),
)

val sampleChanges = listOf(
    Change(41, "device admission: pixel-8", listOf("laptop")),
    Change(40, "subnet grant: 192.168.178.0/24 to nas", listOf("laptop")),
    Change(39, "role grant: relay-capable to vps", listOf("laptop")),
)

val sampleDiagnosis = Diagnosis(
    established = 3, lastEstablished = NOW - 3600,
    dns = DnsDiagnosis(
        queries = 1532, failed = 2, slow = 1, maxMillis = 3000,
        recent = listOf(
            Lookup(NOW - 1800, "mtalk.google.com", "AAAA", "i/o timeout", 3000),
            Lookup(NOW - 600, "example.org", "A", "", 1240),
        ),
    ),
)

/** A second network the phone is in, in slot 1, waiting for its other devices. */
val officeView = NetworkView(
    slot = 1,
    state = State.Waiting,
    network = "office",
    self = Member(identity = "nid:CAAA", name = "pixel-8", v4 = "198.18.140.9", v6 = "fd7e:21c0:9a4:3b1f:6e82:d5a0:c47b:1e93", reach = Reach.Self),
    members = listOf(Member("nid:CQAA", "build", "198.18.140.1", reach = Reach.Sought)),
)

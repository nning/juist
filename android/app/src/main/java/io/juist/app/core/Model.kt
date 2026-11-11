package io.juist.app.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** The core's status as the app shows it: mobile/view.go's view, field for field. */
@Serializable
data class NetworkView(
    /** The network's slot in the core, 0 for the phone's first. */
    val slot: Int = 0,
    val state: State = State.Unknown,
    val network: String = "",
    val detail: String = "",
    val self: Member = Member(),
    val members: List<Member> = emptyList(),
    val fresh: Freshness = Freshness(),
    val tunnels: Tunnels = Tunnels(),
    val exit: ExitView? = null,
    val names: NamesView? = null,
    val alarms: List<Alarm> = emptyList(),
    val updated: Long = 0,
    val settings: PhoneSettings = PhoneSettings(),
    val details: Details = Details(),
    /** The network's admin keys, by which the app tells the networks it holds a key of. */
    val admins: List<String> = emptyList(),
    /** How many changes wait for votes on this phone. */
    val waiting: Int = 0,
) {
    val inNetwork get() = state != State.None && state != State.Joining && state != State.Unknown
}

/** How the device stands, in the order `juist status` lets one win over the next. */
@Serializable
enum class State {
    @SerialName("none") None,
    @SerialName("joining") Joining,
    @SerialName("disabled") Disabled,
    @SerialName("unstarted") Unstarted,
    @SerialName("removed") Removed,
    @SerialName("disconnected") Disconnected,
    @SerialName("refused") Refused,
    @SerialName("limited") Limited,
    @SerialName("waiting") Waiting,
    @SerialName("notunnel") NoTunnel,
    @SerialName("connected") Connected,
    Unknown;

    /** Whether nothing is left of the network on this phone but forgetting it. */
    val ended get() = this == Removed || this == Disabled
}

@Serializable
data class Member(
    val identity: String = "",
    val name: String = "",
    val v4: String = "",
    val v6: String = "",
    val roles: List<String> = emptyList(),
    val retiring: String = "",
    val retiringUntil: Long = 0,
    val reach: Reach = Reach.Unknown,
    /** The member whose relay carries the traffic to it, where [reach] is [Reach.Relay]. */
    val relay: String = "",
    /** Whether [relay] is one of Tailscale’s public DERP servers, no member’s. */
    val relayPublic: Boolean = false,
    val heard: Long = 0,
    val since: Long = 0,
    /** Its name under the network's domain, where it has one. */
    val dns: String = "",
    /** The names published on it, NAME:PORT for one passed by TCP; [membersOnly] those for members alone. */
    val published: List<String> = emptyList(),
    val membersOnly: List<String> = emptyList(),
    /** The public names pointed at it, and the subnets it routes. */
    val names: List<String> = emptyList(),
    val subnets: List<String> = emptyList(),
    /** The newest schema its juist implements, 0 where it says none. */
    val build: Int = 0,
)

/**
 * The phone's own settings: whether its lookups go to juist, whether it resolves the public names the network
 * points at members to them, whether it reaches relays by HTTPS alone, and whether it has the router open a port
 * for it.
 */
@Serializable
data class PhoneSettings(
    val names: Boolean = true,
    val publicNames: Boolean = false,
    val httpsOnly: Boolean = false,
    val portMapping: Boolean = true,
)

/** What the data plane measured of the network beneath (ipc.Underlay). */
@Serializable
data class Underlay(
    val udp: Boolean = false,
    val ipv4: Boolean = false,
    val ipv6: Boolean = false,
    /** Whether the measurement told how IPv4's NAT maps; [portPerPeer] how it does. */
    val mapping: Boolean = false,
    val portPerPeer: Boolean = false,
    /** The port mapping protocols the router answered, and the address a mapping holds there. */
    val offered: List<String> = emptyList(),
    val mapped: String = "",
)

/** What `juist status` says beyond the state. */
@Serializable
data class Details(
    val schema: Int = 0,
    val appSchema: Int = 0,
    val epoch: Long = 0,
    val head: String = "",
    val relays: Int = 0,
    val installed: Int = 0,
    val home: String = "",
    val httpsRelays: List<String> = emptyList(),
    /** Whether members meet through Tailscale's public DERP servers where no member relays. */
    val publicDerp: Boolean = false,
    val underlay: Underlay? = null,
    val subnets: List<SubnetRoute> = emptyList(),
)

/** A subnet the network routes through [router], in use on this phone or not, and why. */
@Serializable
data class SubnetRoute(val prefix: String, val router: String = "", val inUse: Boolean = false, val why: String = "")

/** One of the log's changes, as `juist log` lists it. */
@Serializable
data class Change(val index: Int, val what: String, val signers: List<String> = emptyList())

/** What the core says of how the phone's traffic fares (mobile/diagnose.go). */
@Serializable
data class Diagnosis(
    val established: Int = 0,
    val lastEstablished: Long = 0,
    val saving: Boolean = false,
    val dns: DnsDiagnosis = DnsDiagnosis(),
)

@Serializable
data class DnsDiagnosis(
    val queries: Int = 0,
    val failed: Int = 0,
    val slow: Int = 0,
    val maxMillis: Long = 0,
    val recent: List<Lookup> = emptyList(),
)

/** A lookup that failed, [why], or was slow. */
@Serializable
data class Lookup(val at: Long, val name: String, val type: String, val why: String = "", val millis: Long = 0)

/** How the last check reached a member; mobile/view.go's reachOf says when each holds. */
@Serializable
enum class Reach {
    @SerialName("self") Self,
    @SerialName("direct") Direct,
    @SerialName("relay") Relay,
    @SerialName("outdated") Outdated,
    @SerialName("down") Down,
    @SerialName("sought") Sought,
    @SerialName("absent") Absent,
    @SerialName("silent") Silent,
    @SerialName("unchecked") Unchecked,
    @SerialName("unconnected") Unconnected,
    Unknown,
}

@Serializable
data class Freshness(
    val state: FreshState = FreshState.Unknown,
    val since: Long = 0,
    val until: Long = 0,
    val vouching: Int = 0,
    val vouchers: Int = 0,
)

@Serializable
enum class FreshState {
    @SerialName("unenforced") Unenforced,
    @SerialName("fresh") Fresh,
    @SerialName("stale") Stale,
    Unknown,
}

/** The phone's use of exit nodes: the one chosen, or none, how that goes, and those on offer. */
@Serializable
data class ExitView(
    val node: String = "",
    val name: String = "",
    val refused: String = "",
    val failed: String = "",
    val dns: Boolean = false,
    val dnsNot: String = "",
    val partly: String = "",
    val offering: List<Member> = emptyList(),
) {
    val inUse get() = node.isNotEmpty()
}

/**
 * What the phone resolves of the network's names: its domain, the phone's own names, whether its lookups reach juist,
 * and the public names pointed at other members.
 */
@Serializable
data class NamesView(
    val domain: String = "",
    val own: List<String> = emptyList(),
    val resolved: Boolean = false,
    val public: List<PublicName> = emptyList(),
)

/** A public name the network points at member, and why the phone resolves it publicly now, where it agreed. */
@Serializable
data class PublicName(val name: String = "", val member: String = "", val not: String = "")

@Serializable
data class Tunnels(val live: Int = 0, val total: Int = 0, val checked: Long = 0)

@Serializable
data class Alarm(
    val kind: String,
    val severity: Severity = Severity.Info,
    val names: List<String> = emptyList(),
    val count: Int = 0,
    val text: String = "",
)

@Serializable
enum class Severity {
    @SerialName("alarm") Alarm,
    @SerialName("warn") Warn,
    @SerialName("info") Info,
}

/** Reads what the core writes, taking a value it does not know as Unknown rather than failing. */
val coreJson = Json {
    ignoreUnknownKeys = true
    coerceInputValues = true
}

fun parseView(json: String): NetworkView = coreJson.decodeFromString(NetworkView.serializer(), json)

/** Every network's view, by slot, as the core lists them; one view alone, as earlier apps kept it, is slot 0's. */
fun parseViews(json: String): List<NetworkView> =
    if (json.trimStart().startsWith("[")) {
        coreJson.decodeFromString(ListSerializer(NetworkView.serializer()), json).sortedBy { it.slot }
    } else {
        listOf(parseView(json).copy(slot = 0))
    }

/** An invite the phone offers. */
sealed interface InviteState {
    /** Whether it is open, and another may not start. */
    val open: Boolean get() = this !is Idle && this !is Joined && this !is Ended

    data object Idle : InviteState
    data object Starting : InviteState
    /** Open: the code for the same Wi-Fi, the link a QR code shows; noLan where the code is not announced on the Wi-Fi. */
    data class Offered(val code: String, val link: String, val noLan: Boolean = false) : InviteState
    /** A device asks to join as name: the person compares words with those it shows. */
    data class Comparing(val words: String, val name: String) : InviteState
    data class Admitting(val name: String) : InviteState
    data class Joined(val name: String) : InviteState
    /** Ended unjoined: why, null where it expired or was cancelled; refused where the words differed. */
    data class Ended(val why: String?, val refused: Boolean = false) : InviteState
}

/** host.Joined and host.NoLAN, the invite's events of a device that joined and of a code not on the Wi-Fi. */
internal const val HOST_JOINED = 3
internal const val HOST_NO_LAN = 4

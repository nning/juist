package io.juist.app.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** The core's status as the app shows it: mobile/view.go's view, field for field. */
@Serializable
data class NetworkView(
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
    val heard: Long = 0,
    val since: Long = 0,
    /** Its name under the network's domain, where it has one. */
    val dns: String = "",
)

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

/** What the phone resolves of the network's names: its domain, the phone's own names, and whether its lookups reach juist. */
@Serializable
data class NamesView(
    val domain: String = "",
    val own: List<String> = emptyList(),
    val resolved: Boolean = false,
)

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

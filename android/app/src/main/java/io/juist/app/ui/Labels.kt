package io.juist.app.ui

import android.text.format.DateUtils
import androidx.annotation.StringRes
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import io.juist.app.R
import io.juist.app.core.Alarm
import io.juist.app.core.CoreInviteChecks
import io.juist.app.core.InviteChecks
import io.juist.app.core.FreshState
import io.juist.app.core.Freshness
import io.juist.app.core.Member
import io.juist.app.core.Reach
import io.juist.app.core.State
import io.juist.app.ui.theme.LocalStatusColors

/** What screens check invites with; tests give their own. */
val LocalInviteChecks = staticCompositionLocalOf<InviteChecks> { CoreInviteChecks }

/** The time screens count from, in Unix seconds; tests fix it. */
val LocalNow = staticCompositionLocalOf { System.currentTimeMillis() / 1000 }

@StringRes
fun stateLabel(s: State): Int = when (s) {
    State.None -> R.string.state_none
    State.Joining -> R.string.state_joining
    State.Unstarted -> R.string.state_unstarted
    State.Disabled -> R.string.state_disabled
    State.Removed -> R.string.state_removed
    State.Disconnected -> R.string.state_disconnected
    State.Refused -> R.string.state_refused
    State.Limited -> R.string.state_limited
    State.Waiting -> R.string.state_waiting
    State.NoTunnel -> R.string.state_notunnel
    State.Connected -> R.string.state_connected
    State.Unknown -> R.string.state_starting
}

/** What a state means, null where its name says it all. */
@StringRes
fun stateExplanation(s: State): Int? = when (s) {
    State.Unstarted -> R.string.state_unstarted_about
    State.Disabled -> R.string.state_disabled_about
    State.Removed -> R.string.state_removed_about
    State.Disconnected -> R.string.state_disconnected_about
    State.Refused -> R.string.state_refused_about
    State.Limited -> R.string.state_limited_about
    State.Waiting -> R.string.state_waiting_about
    State.NoTunnel -> R.string.state_notunnel_about
    State.Connected -> null
    else -> R.string.state_starting_about
}

@Composable
@ReadOnlyComposable
fun stateColor(s: State): Color {
    val status = LocalStatusColors.current
    return when (s) {
        State.Connected -> status.direct
        State.Limited, State.Waiting, State.NoTunnel -> status.relay
        State.Disabled, State.Removed, State.Disconnected, State.Refused, State.Unstarted -> status.alarm
        else -> status.absent
    }
}

@Composable
@ReadOnlyComposable
fun reachColor(r: Reach): Color {
    val status = LocalStatusColors.current
    return when (r) {
        Reach.Direct -> status.direct
        Reach.Relay -> status.relay
        Reach.Sought, Reach.Unchecked -> status.sought
        Reach.Down, Reach.Unconnected, Reach.Outdated -> status.alarm
        Reach.Self -> MaterialTheme.colorScheme.primary
        else -> status.absent
    }
}

/** How a member was reached, in a few words, as `juist devices` says it. */
@Composable
fun reachLabel(m: Member): String = when (m.reach) {
    Reach.Self -> stringResource(R.string.reach_self)
    Reach.Direct -> stringResource(R.string.reach_direct)
    Reach.Relay -> stringResource(R.string.reach_relay)
    Reach.Outdated -> stringResource(R.string.reach_outdated)
    Reach.Down -> stringResource(R.string.reach_down)
    Reach.Sought -> stringResource(R.string.reach_sought)
    Reach.Absent -> if (m.heard > 0) stringResource(R.string.reach_absent_heard, ago(m.heard)) else stringResource(R.string.reach_absent)
    Reach.Silent -> stringResource(R.string.reach_silent)
    Reach.Unchecked -> stringResource(R.string.reach_unchecked)
    Reach.Unconnected -> stringResource(R.string.reach_unconnected)
    Reach.Unknown -> stringResource(R.string.reach_unknown)
}

/** What a member's reach means, for its own screen; null where its name says it all. */
@Composable
fun reachExplanation(m: Member): String? = when {
    m.reach == Reach.Relay && m.relay.isNotEmpty() -> stringResource(R.string.reach_relay_about_named, m.relay)
    else -> reachExplanationOf(m.reach)?.let { stringResource(it) }
}

@StringRes
private fun reachExplanationOf(r: Reach): Int? = when (r) {
    Reach.Relay -> R.string.reach_relay_about
    Reach.Outdated -> R.string.reach_outdated_about
    Reach.Down -> R.string.reach_down_about
    Reach.Sought -> R.string.reach_sought_about
    Reach.Absent -> R.string.reach_absent_about
    Reach.Silent -> R.string.reach_silent_about
    Reach.Unconnected -> R.string.reach_unconnected_about
    else -> null
}

/** A role the log gives, by the name the CLI grants it under. */
@Composable
fun roleLabel(role: String): String = when (role) {
    "admin" -> stringResource(R.string.role_voucher)
    "relay-capable" -> stringResource(R.string.role_relay)
    "exit" -> stringResource(R.string.role_exit)
    "ingress" -> stringResource(R.string.role_ingress)
    "publish" -> stringResource(R.string.role_publish)
    "service" -> stringResource(R.string.role_service)
    else -> role
}

/** "4 minutes ago", or "just now", from Unix seconds, to go inside a sentence; or to stand alone, capitalised. */
@Composable
fun ago(unix: Long, alone: Boolean = false): String {
    val now = LocalNow.current
    val s = if (now - unix < 60) {
        stringResource(R.string.just_now)
    } else {
        DateUtils.getRelativeTimeSpanString(unix * 1000, now * 1000, DateUtils.MINUTE_IN_MILLIS).toString()
    }
    return if (alone) s.replaceFirstChar { it.titlecase() } else s.replaceFirstChar { it.lowercase() }
}

/** "47 hours", "3 days": how long from now until unix. */
@Composable
fun lasting(unix: Long): String {
    val left = (unix - LocalNow.current).coerceAtLeast(0)
    val hours = (left / 3600).toInt()
    return when {
        hours >= 72 -> pluralStringResource(R.plurals.days, hours / 24, hours / 24)
        hours >= 1 -> pluralStringResource(R.plurals.hours, hours, hours)
        else -> pluralStringResource(R.plurals.minutes, (left / 60).toInt(), (left / 60).toInt())
    }
}

@Composable
fun freshnessText(f: Freshness): String = when (f.state) {
    FreshState.Unenforced -> stringResource(R.string.fresh_unenforced)
    FreshState.Stale -> if (f.vouchers > 1) {
        pluralStringResource(R.plurals.fresh_stale_of, f.vouchers, f.vouching, f.vouchers)
    } else {
        stringResource(R.string.fresh_stale)
    }
    FreshState.Fresh -> if (f.until > 0) {
        if (f.vouchers > 1) {
            pluralStringResource(R.plurals.fresh_vouched_by, f.vouching, f.vouching, ago(f.since), lasting(f.until))
        } else {
            stringResource(R.string.fresh_vouched, ago(f.since), lasting(f.until))
        }
    } else {
        stringResource(R.string.fresh_unchecked)
    }
    FreshState.Unknown -> stringResource(R.string.fresh_unchecked)
}

/** A list of names as a sentence would have them. */
@Composable
fun names(list: List<String>): String = when (list.size) {
    0 -> ""
    1 -> list[0]
    else -> stringResource(R.string.list_and, list.dropLast(1).joinToString(", "), list.last())
}

/** An alarm in the app's words; the daemon's own, in English, follows where it gave any. */
@Composable
fun alarmTitle(a: Alarm): String = when (a.kind) {
    "fork" -> stringResource(R.string.alarm_fork)
    "schema" -> stringResource(R.string.alarm_schema)
    "staleKeys" -> stringResource(R.string.alarm_stale_keys)
    "refused" -> stringResource(R.string.alarm_refused)
    "epoch" -> stringResource(R.string.alarm_epoch)
    "dataPlane" -> stringResource(R.string.alarm_data_plane)
    "noTraffic" -> stringResource(R.string.alarm_no_traffic, names(a.names))
    "newer" -> stringResource(R.string.alarm_newer, names(a.names))
    "outdated" -> stringResource(R.string.alarm_outdated, names(a.names))
    "older" -> stringResource(R.string.alarm_older, names(a.names))
    "conflicted" -> pluralStringResource(R.plurals.alarm_conflicted, a.count, a.count)
    "noRelay" -> stringResource(R.string.alarm_no_relay)
    "freshnessEnding" -> pluralStringResource(R.plurals.alarm_freshness_ending, a.count, a.count)
    "lost" -> stringResource(R.string.alarm_lost)
    "unrevoked" -> stringResource(R.string.alarm_unrevoked)
    "silent" -> if (a.names.isNotEmpty()) {
        stringResource(R.string.alarm_silent, names(a.names))
    } else {
        pluralStringResource(R.plurals.alarm_silent_count, a.count, a.count)
    }
    "seeking" -> stringResource(R.string.alarm_seeking, names(a.names))
    else -> a.kind
}

/** What to do about an alarm, where anything is to be done on the phone. */
@StringRes
fun alarmHint(a: Alarm): Int? = when (a.kind) {
    "fork" -> R.string.alarm_fork_hint
    "schema" -> R.string.alarm_schema_hint
    "staleKeys" -> R.string.alarm_stale_keys_hint
    "refused" -> R.string.alarm_refused_hint
    "noTraffic" -> R.string.alarm_no_traffic_hint
    "newer" -> R.string.alarm_newer_hint
    "outdated" -> R.string.alarm_outdated_hint
    "older" -> R.string.alarm_older_hint
    "noRelay" -> R.string.alarm_no_relay_hint
    "freshnessEnding" -> R.string.alarm_freshness_ending_hint
    "unrevoked" -> R.string.alarm_unrevoked_hint
    else -> null
}

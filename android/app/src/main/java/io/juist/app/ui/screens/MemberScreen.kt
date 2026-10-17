package io.juist.app.ui.screens

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import io.juist.app.R
import io.juist.app.core.Member
import io.juist.app.core.Reach
import io.juist.app.ui.ago
import io.juist.app.ui.components.BackBar
import io.juist.app.ui.components.CopyRow
import io.juist.app.ui.components.InfoRow
import io.juist.app.ui.components.Panel
import io.juist.app.ui.components.Readable
import io.juist.app.ui.components.SectionTitle
import io.juist.app.ui.components.StatusDot
import io.juist.app.ui.components.Tag
import io.juist.app.ui.reachColor
import io.juist.app.ui.reachExplanation
import io.juist.app.ui.reachLabel
import io.juist.app.ui.roleLabel
import io.juist.app.ui.theme.LocalStatusColors
import io.juist.app.ui.theme.MonoBody
import io.juist.app.ui.theme.Space
import kotlinx.coroutines.launch

/** One echo's outcome: its round trip, or why none came back. */
data class PingResult(val millis: Double?, val error: String? = null)

/** A member: how it is reached, its addresses, and a ping through the tunnel. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun MemberScreen(
    member: Member,
    on: Boolean,
    pings: List<PingResult>,
    pinging: Boolean,
    onPing: () -> Unit,
    onOpen: (String) -> Unit,
    onBack: () -> Unit,
) {
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val copiedText = stringResource(R.string.copied)
    val copied: (String) -> Unit = { scope.launch { snackbar.showSnackbar(copiedText.format(it)) } }
    Scaffold(
        topBar = { BackBar(member.name, onBack) },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize()) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = Space.xxl)) {
                Panel(Modifier.padding(top = Space.s)) {
                    Row(Modifier.padding(Space.l), verticalAlignment = Alignment.CenterVertically) {
                        StatusDot(if (on) reachColor(member.reach) else LocalStatusColors.current.absent, size = 14.dp)
                        Spacer(Modifier.width(Space.m))
                        Text(
                            if (on) reachLabel(member) else stringResource(R.string.reach_off),
                            style = MaterialTheme.typography.titleLarge,
                        )
                    }
                    val about = reachExplanation(member)
                    if (on && about != null) {
                        Text(
                            about,
                            Modifier.padding(start = Space.l, end = Space.l, bottom = Space.l),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (member.roles.isNotEmpty()) {
                        FlowRow(
                            Modifier.padding(start = Space.l, end = Space.l, bottom = Space.l),
                            horizontalArrangement = Arrangement.spacedBy(Space.xs),
                        ) { for (r in member.roles) Tag(roleLabel(r)) }
                    }
                }

                SectionTitle(stringResource(R.string.section_addresses))
                Panel {
                    if (member.v4.isNotEmpty()) CopyRow(stringResource(R.string.label_ipv4), member.v4, copied)
                    if (member.retiring.isNotEmpty()) {
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        CopyRow(stringResource(R.string.label_ipv4_retiring), member.retiring, copied)
                    }
                    if (member.v6.isNotEmpty()) {
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        CopyRow(stringResource(R.string.label_ipv6), member.v6, copied)
                    }
                    if (member.heard > 0) {
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        InfoRow(stringResource(R.string.label_heard), ago(member.heard, alone = true))
                    }
                    if (member.since > 0 && member.reach != Reach.Direct && member.reach != Reach.Relay) {
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        InfoRow(stringResource(R.string.label_down_since), ago(member.since, alone = true))
                    }
                }

                SectionTitle(stringResource(R.string.section_reach))
                // A ping passes an outdated member's filter; no other app does.
                val outdated = member.reach == Reach.Outdated
                Panel(Modifier.animateContentSize()) {
                    Text(
                        stringResource(if (outdated) R.string.ping_about_outdated else R.string.ping_about),
                        Modifier.padding(Space.l),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    for ((i, p) in pings.withIndex()) {
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        PingRow(pings.size - i, p)
                    }
                    Column(
                        Modifier.fillMaxWidth().padding(Space.l),
                        verticalArrangement = Arrangement.spacedBy(Space.s),
                    ) {
                        Button(onPing, Modifier.fillMaxWidth(), enabled = on && !pinging) {
                            if (pinging) {
                                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(painterResource(R.drawable.ic_ping), null, Modifier.size(18.dp))
                            }
                            Spacer(Modifier.width(Space.s))
                            Text(stringResource(R.string.action_ping))
                        }
                        val address = member.v4.ifEmpty { member.v6.takeIf { it.isNotEmpty() }?.let { "[$it]" } }
                        if (address != null) {
                            OutlinedButton({ onOpen("http://$address/") }, Modifier.fillMaxWidth(), enabled = on && !outdated) {
                                Icon(painterResource(R.drawable.ic_open), null, Modifier.size(18.dp))
                                Spacer(Modifier.width(Space.s))
                                Text(stringResource(R.string.action_open_web))
                            }
                        }
                    }
                }

                SectionTitle(stringResource(R.string.section_identity))
                Panel {
                    CopyRow(stringResource(R.string.label_identity), member.identity, copied)
                }
                Spacer(Modifier.height(Space.l))
            }
        }
    }
}

@Composable
private fun PingRow(n: Int, p: PingResult) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.m).semantics { liveRegion = LiveRegionMode.Polite },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        StatusDot(if (p.millis != null) LocalStatusColors.current.direct else LocalStatusColors.current.alarm, size = 8.dp)
        Spacer(Modifier.width(Space.m))
        Text("#$n", style = MonoBody, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(Space.m))
        if (p.millis != null) {
            Text(stringResource(R.string.ping_ms, p.millis), style = MonoBody)
        } else {
            Text(stringResource(R.string.ping_failed, p.error.orEmpty()), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

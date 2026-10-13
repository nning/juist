package io.juist.app.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.TextButton
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.juist.app.R
import io.juist.app.core.Alarm
import io.juist.app.core.Connection
import io.juist.app.core.lastView
import io.juist.app.core.Member
import io.juist.app.core.NetworkView
import io.juist.app.core.OffReason
import io.juist.app.core.Reach
import io.juist.app.core.Severity
import io.juist.app.core.State
import io.juist.app.ui.alarmHint
import io.juist.app.ui.alarmTitle
import io.juist.app.ui.ago
import io.juist.app.ui.components.CopyRow
import io.juist.app.ui.components.InfoRow
import io.juist.app.ui.components.Panel
import io.juist.app.ui.components.Readable
import io.juist.app.ui.components.SectionTitle
import io.juist.app.ui.components.StatusDot
import io.juist.app.ui.components.Tag
import io.juist.app.ui.freshnessText
import io.juist.app.ui.reachColor
import io.juist.app.ui.reachLabel
import io.juist.app.ui.roleLabel
import io.juist.app.ui.stateColor
import io.juist.app.ui.stateExplanation
import io.juist.app.ui.stateLabel
import io.juist.app.ui.theme.LocalStatusColors
import io.juist.app.ui.theme.Motion
import io.juist.app.ui.theme.Space
import kotlinx.coroutines.launch

/** The network, this device and every member as last reached, and what needs attention. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StatusScreen(
    connection: Connection,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onMember: (Member) -> Unit,
    onAbout: () -> Unit,
    onForget: () -> Unit,
    onStartOver: () -> Unit = {},
    onExit: (String?) -> Unit = {},
    onVpnSettings: () -> Unit = {},
) {
    val view = connection.lastView
    val on = connection is Connection.On
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val copiedText = stringResource(R.string.copied)
    val copied: (String) -> Unit = { scope.launch { snackbar.showSnackbar(copiedText.format(it)) } }
    var menu by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        view?.network?.takeIf { it.isNotEmpty() } ?: stringResource(R.string.app_name),
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                },
                actions = {
                    IconButton({ menu = true }) { Icon(Icons.Filled.MoreVert, stringResource(R.string.action_more)) }
                    DropdownMenu(menu, { menu = false }) {
                        DropdownMenuItem({ Text(stringResource(R.string.about_title)) }, { menu = false; onAbout() })
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize()) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = Space.xxl)) {
                Hero(connection, view, onConnect, onDisconnect, onForget, onStartOver)
                if (on && view != null) {
                    for (a in view.alarms) AlarmCard(a)
                }
                // A removed device, or one in a disabled network, has nothing
                // left to show but how to start over.
                if (view != null && view.inNetwork && !(on && view.state.ended)) {
                    SectionTitle(stringResource(R.string.section_this_device))
                    ThisDevice(view, on, copied)
                    view.exit?.let { ExitSection(it, on, onExit, onVpnSettings) }
                    Members(view, on, onMember)
                }
            }
        }
    }
}

@Composable
private fun Hero(
    connection: Connection,
    view: NetworkView?,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onForget: () -> Unit,
    onStartOver: () -> Unit,
) {
    var confirm by remember { mutableStateOf(false) }
    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text(stringResource(R.string.start_over_title)) },
            text = { Text(stringResource(R.string.start_over_body)) },
            confirmButton = {
                TextButton({ confirm = false; onStartOver() }) { Text(stringResource(R.string.action_start_over)) }
            },
            dismissButton = { TextButton({ confirm = false }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }
    val on = connection is Connection.On
    val starting = connection is Connection.Starting
    val state = (connection as? Connection.On)?.view?.state
    val title: String
    val body: String?
    val color: Color
    when (connection) {
        is Connection.On -> {
            title = stringResource(stateLabel(connection.view.state))
            val about = stateExplanation(connection.view.state)?.let { stringResource(it) }
            body = if (connection.view.state == State.Unstarted && connection.view.detail.isNotEmpty()) {
                listOfNotNull(about, connection.view.detail).joinToString("\n")
            } else {
                about
            }
            color = stateColor(connection.view.state)
        }
        is Connection.Starting -> {
            title = stringResource(R.string.state_starting)
            body = stringResource(R.string.state_starting_about)
            color = LocalStatusColors.current.sought
        }
        is Connection.Failed -> {
            title = stringResource(R.string.state_failed)
            body = connection.message
            color = LocalStatusColors.current.alarm
        }
        is Connection.Off -> {
            title = stringResource(R.string.state_vpn_off)
            body = stringResource(if (connection.reason == OffReason.Revoked) R.string.state_revoked_about else R.string.state_vpn_off_about)
            color = LocalStatusColors.current.absent
        }
    }
    val animated by animateColorAsState(color, tween(Motion.MEDIUM), label = "state")
    val vpn = stringResource(R.string.vpn_switch)
    Panel(Modifier.padding(top = Space.s)) {
        Row(Modifier.padding(Space.l), verticalAlignment = Alignment.CenterVertically) {
            StatusDot(animated, size = 14.dp, pulse = starting || state == State.Waiting)
            Spacer(Modifier.width(Space.m))
            Text(
                title, Modifier.weight(1f).semantics { heading() },
                style = MaterialTheme.typography.headlineSmall,
            )
            Switch(
                checked = on || starting,
                onCheckedChange = { if (it) onConnect() else onDisconnect() },
                modifier = Modifier.semantics { contentDescription = vpn },
            )
        }
        if (!body.isNullOrEmpty()) {
            Text(
                body,
                Modifier.padding(start = Space.l, end = Space.l, bottom = Space.l),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (on && state?.ended == true) {
            Button(onForget, Modifier.fillMaxWidth().padding(start = Space.l, end = Space.l, bottom = Space.l)) {
                Text(stringResource(R.string.action_forget))
            }
        }
        if (connection is Connection.Failed) {
            OutlinedButton({ confirm = true }, Modifier.fillMaxWidth().padding(start = Space.l, end = Space.l, bottom = Space.l)) {
                Text(stringResource(R.string.action_start_over))
            }
        }
        if (connection is Connection.Off && view?.inNetwork == true) {
            Button(onConnect, Modifier.fillMaxWidth().padding(start = Space.l, end = Space.l, bottom = Space.l)) {
                Icon(painterResource(R.drawable.ic_power), null, Modifier.size(18.dp))
                Spacer(Modifier.width(Space.s))
                Text(stringResource(R.string.action_connect))
            }
        }
    }
}

@Composable
private fun AlarmCard(a: Alarm) {
    val (container, content) = when (a.severity) {
        Severity.Alarm -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
        Severity.Warn -> MaterialTheme.colorScheme.secondaryContainer to MaterialTheme.colorScheme.onSecondaryContainer
        Severity.Info -> MaterialTheme.colorScheme.surfaceContainer to MaterialTheme.colorScheme.onSurface
    }
    val dot = when (a.severity) {
        Severity.Alarm -> LocalStatusColors.current.alarm
        Severity.Warn -> LocalStatusColors.current.relay
        Severity.Info -> LocalStatusColors.current.sought
    }
    Surface(
        Modifier.fillMaxWidth().padding(start = Space.l, end = Space.l, top = Space.m),
        shape = MaterialTheme.shapes.medium,
        color = container,
    ) {
        Row(Modifier.padding(Space.l)) {
            StatusDot(dot, Modifier.padding(top = 6.dp))
            Spacer(Modifier.width(Space.m))
            Column {
                Text(alarmTitle(a), style = MaterialTheme.typography.titleSmall, color = content)
                alarmHint(a)?.let {
                    Text(stringResource(it), style = MaterialTheme.typography.bodyMedium, color = content)
                }
                if (a.text.isNotEmpty()) {
                    Spacer(Modifier.height(Space.xs))
                    Text(a.text, style = MaterialTheme.typography.bodySmall, color = content.copy(alpha = 0.8f))
                }
            }
        }
    }
}

@Composable
private fun ThisDevice(view: NetworkView, on: Boolean, copied: (String) -> Unit) {
    Panel {
        InfoRow(stringResource(R.string.label_name), view.self.name)
        if (view.self.v4.isNotEmpty()) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            CopyRow(stringResource(R.string.label_ipv4), view.self.v4, copied)
        }
        if (view.self.retiring.isNotEmpty()) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            CopyRow(stringResource(R.string.label_ipv4_retiring), view.self.retiring, copied)
        }
        if (view.self.v6.isNotEmpty()) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            CopyRow(stringResource(R.string.label_ipv6), view.self.v6, copied)
        }
        if (on) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            InfoRow(stringResource(R.string.label_freshness), freshnessText(view.fresh))
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun Members(view: NetworkView, on: Boolean, onMember: (Member) -> Unit) {
    SectionTitle(pluralStringResource(R.plurals.section_devices, view.members.size, view.members.size))
    if (view.members.isEmpty()) {
        Panel {
            Text(
                stringResource(R.string.members_none),
                Modifier.padding(Space.l),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        return
    }
    Panel {
        view.members.forEachIndexed { i, m ->
            if (i > 0) HorizontalDivider(Modifier.padding(start = 44.dp), color = MaterialTheme.colorScheme.outlineVariant)
            val reach = if (on) reachLabel(m) else stringResource(R.string.reach_off)
            Row(
                Modifier
                    .fillMaxWidth()
                    .clickable(role = Role.Button) { onMember(m) }
                    .padding(horizontal = Space.l, vertical = Space.m)
                    .semantics(mergeDescendants = true) { stateDescription = reach },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                StatusDot(if (on) reachColor(m.reach) else LocalStatusColors.current.absent, pulse = on && m.reach == Reach.Sought)
                Spacer(Modifier.width(Space.l))
                Column(Modifier.weight(1f)) {
                    Text(m.name, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (on) Text(reach, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (m.roles.isNotEmpty()) {
                        FlowRow(Modifier.padding(top = Space.xs), horizontalArrangement = Arrangement.spacedBy(Space.xs)) {
                            for (r in m.roles) Tag(roleLabel(r))
                        }
                    }
                }
                Icon(
                    Icons.AutoMirrored.Filled.KeyboardArrowRight, null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
    if (on && view.tunnels.checked > 0) {
        Text(
            stringResource(R.string.members_checked, ago(view.tunnels.checked)),
            Modifier.padding(horizontal = Space.xl, vertical = Space.m),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

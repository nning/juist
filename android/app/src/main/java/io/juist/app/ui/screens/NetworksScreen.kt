package io.juist.app.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.juist.app.R
import io.juist.app.core.Connection
import io.juist.app.core.MAX_NETWORKS
import io.juist.app.core.NetworkView
import io.juist.app.core.Severity
import io.juist.app.core.networks
import io.juist.app.ui.components.Panel
import io.juist.app.ui.components.Readable
import io.juist.app.ui.components.SectionTitle
import io.juist.app.ui.components.StatusDot
import io.juist.app.ui.stateColor
import io.juist.app.ui.stateLabel
import io.juist.app.ui.theme.LocalStatusColors
import io.juist.app.ui.theme.Space

/** The networks the phone is in, each as it fares, and the VPN that carries them all. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NetworksScreen(
    connection: Connection,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onNetwork: (Int) -> Unit,
    onJoinAnother: () -> Unit,
    onAbout: () -> Unit,
    onStartOver: () -> Unit = {},
    saving: Boolean = false,
) {
    val on = connection is Connection.On
    val networks = connection.networks
    var menu by remember { mutableStateOf(false) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.app_name)) },
                actions = {
                    IconButton({ menu = true }) { Icon(Icons.Filled.MoreVert, stringResource(R.string.action_more)) }
                    DropdownMenu(menu, { menu = false }) {
                        DropdownMenuItem({ Text(stringResource(R.string.about_title)) }, { menu = false; onAbout() })
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize()) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = Space.xxl)) {
                Hero(connection, null, onConnect, onDisconnect, {}, onStartOver, overall = true)
                if (on && saving) NoteCard(Severity.Info, stringResource(R.string.saving), stringResource(R.string.saving_hint))
                SectionTitle(stringResource(R.string.section_networks))
                Panel {
                    networks.forEachIndexed { i, v ->
                        if (i > 0) HorizontalDivider(Modifier.padding(start = 44.dp), color = MaterialTheme.colorScheme.outlineVariant)
                        NetworkRow(v, on) { onNetwork(v.slot) }
                    }
                }
                if (networks.size < MAX_NETWORKS) {
                    OutlinedButton(onJoinAnother, Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.l).heightIn(min = 48.dp)) {
                        Icon(painterResource(R.drawable.ic_qr), null, Modifier.size(18.dp))
                        Spacer(Modifier.width(Space.s))
                        Text(stringResource(R.string.action_join_another))
                    }
                } else {
                    Text(
                        stringResource(R.string.networks_most, MAX_NETWORKS),
                        Modifier.padding(horizontal = Space.xl, vertical = Space.l),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun NetworkRow(v: NetworkView, on: Boolean, onClick: () -> Unit) {
    val state = if (on) stringResource(stateLabel(v.state)) else stringResource(R.string.reach_off)
    val warned = on && v.alarms.any { it.severity != Severity.Info }
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = Space.l, vertical = Space.m)
            .semantics(mergeDescendants = true) { stateDescription = state },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        StatusDot(if (on) stateColor(v.state) else LocalStatusColors.current.absent)
        Spacer(Modifier.width(Space.l))
        Column(Modifier.weight(1f)) {
            Text(v.network.ifEmpty { stringResource(R.string.app_name) }, style = MaterialTheme.typography.titleMedium,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                listOf(state, v.self.name).filter { it.isNotEmpty() }.joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = if (warned) LocalStatusColors.current.relay else MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1, overflow = TextOverflow.Ellipsis,
            )
        }
        Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

package io.juist.app.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import io.juist.app.R
import io.juist.app.core.ExitView
import io.juist.app.core.Member
import io.juist.app.ui.components.Panel
import io.juist.app.ui.components.SectionTitle
import io.juist.app.ui.reachLabel
import io.juist.app.ui.theme.Space

/**
 * Where the phone's internet goes: directly, or through one of the exit nodes
 * on offer, and how that goes. While one is chosen and cannot be used, the
 * internet is refused rather than sent around it.
 */
@Composable
fun ExitSection(exit: ExitView, on: Boolean, onExit: (String?) -> Unit, onVpnSettings: () -> Unit) {
    SectionTitle(stringResource(R.string.section_internet))
    Panel {
        Column(Modifier.selectableGroup()) {
            Choice(stringResource(R.string.exit_direct), "", !exit.inUse, on) { onExit(null) }
            val offered = exit.offering.toMutableList()
            if (exit.inUse && offered.none { it.identity == exit.node }) {
                offered += Member(identity = exit.node, name = exit.name.ifEmpty { exit.node.take(12) })
            }
            for (m in offered) {
                Choice(m.name, if (on) reachLabel(m) else "", exit.node == m.identity, on) { onExit(m.identity) }
            }
        }
        if (exit.inUse && on) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            val (text, bad) = when {
                exit.failed.isNotEmpty() -> stringResource(R.string.exit_failed, exit.failed) to true
                exit.refused.isNotEmpty() -> stringResource(R.string.exit_refused, exit.refused) to true
                exit.partly.isNotEmpty() -> stringResource(R.string.exit_partly, exit.partly) to true
                exit.dns -> stringResource(R.string.exit_through, exit.name) to false
                else -> stringResource(R.string.exit_through_no_dns, exit.name, exit.dnsNot) to false
            }
            Text(
                text,
                Modifier.padding(Space.l),
                style = MaterialTheme.typography.bodyMedium,
                color = if (bad) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            )
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Text(
                stringResource(R.string.exit_always_on),
                Modifier.padding(start = Space.l, end = Space.l, top = Space.l),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            TextButton(onVpnSettings, Modifier.padding(horizontal = Space.s)) { Text(stringResource(R.string.action_vpn_settings)) }
        }
    }
}

@Composable
private fun Choice(title: String, subtitle: String, selected: Boolean, enabled: Boolean, onSelect: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .selectable(selected = selected, enabled = enabled, role = Role.RadioButton, onClick = onSelect)
            .padding(horizontal = Space.l, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null, enabled = enabled)
        Spacer(Modifier.width(Space.m))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            if (subtitle.isNotEmpty()) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

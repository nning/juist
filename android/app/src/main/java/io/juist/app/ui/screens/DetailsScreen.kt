package io.juist.app.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import io.juist.app.R
import io.juist.app.core.Change
import io.juist.app.core.Diagnosis
import io.juist.app.core.NetworkView
import io.juist.app.ui.ago
import io.juist.app.ui.components.BackBar
import io.juist.app.ui.components.InfoRow
import io.juist.app.ui.components.Panel
import io.juist.app.ui.components.Readable
import io.juist.app.ui.components.SectionTitle
import io.juist.app.ui.theme.MonoBody
import io.juist.app.ui.theme.Space
import kotlinx.coroutines.launch

/**
 * What `juist status` and the status page say beyond the state: the phone's
 * settings, the network's schema and log, its relays and subnets, and how
 * the phone's traffic fares, for a report.
 */
@Composable
fun DetailsScreen(
    view: NetworkView,
    on: Boolean,
    changes: List<Change>?,
    diagnosis: Diagnosis?,
    onNames: (Boolean) -> Unit,
    onHttpsOnly: (Boolean) -> Unit,
    onCopyReport: () -> Unit,
    onBack: () -> Unit,
) {
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val copied = stringResource(R.string.log_copied)
    val d = view.details
    Scaffold(
        topBar = { BackBar(stringResource(R.string.details_title), onBack) },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize()) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = Space.xxl)) {
                SectionTitle(stringResource(R.string.section_settings))
                Panel {
                    SwitchRow(stringResource(R.string.setting_names), stringResource(R.string.setting_names_about),
                        view.settings.names, on, onNames)
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    SwitchRow(stringResource(R.string.setting_https_only), stringResource(R.string.setting_https_only_about),
                        view.settings.httpsOnly, on, onHttpsOnly)
                }

                SectionTitle(stringResource(R.string.section_network))
                Panel {
                    if (d.schema > 0) {
                        InfoRow(stringResource(R.string.label_schema), stringResource(R.string.schema_value, d.schema, d.appSchema))
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    }
                    if (d.head.isNotEmpty()) {
                        InfoRow(stringResource(R.string.label_log), stringResource(R.string.log_value, d.head, d.epoch))
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    }
                    if (view.updated > 0) {
                        InfoRow(stringResource(R.string.label_updated), ago(view.updated, alone = true))
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    }
                    InfoRow(stringResource(R.string.label_relays), relaysText(view))
                    if (view.names != null) {
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        InfoRow(stringResource(R.string.label_names), namesText(view))
                    }
                }

                if (d.subnets.isNotEmpty()) {
                    SectionTitle(stringResource(R.string.section_subnets))
                    Panel {
                        d.subnets.forEachIndexed { i, s ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                            val state = if (s.inUse) stringResource(R.string.subnet_in_use) else stringResource(R.string.subnet_not_in_use)
                            InfoRow(
                                stringResource(R.string.subnet_via, s.prefix, s.router),
                                listOf(state, s.why).filter { it.isNotEmpty() }.joinToString(": "),
                            )
                        }
                    }
                }

                if (!changes.isNullOrEmpty()) {
                    SectionTitle(stringResource(R.string.section_changes))
                    Panel {
                        changes.forEachIndexed { i, c ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                            Row(Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.s)) {
                                Text("#${c.index}", style = MonoBody, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Spacer(Modifier.width(Space.m))
                                Text(c.what, style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                    }
                }

                SectionTitle(stringResource(R.string.section_diagnosis))
                Panel {
                    if (diagnosis != null) {
                        InfoRow(
                            stringResource(R.string.label_vpn_established),
                            pluralStringResource(R.plurals.vpn_established, diagnosis.established, diagnosis.established) +
                                (if (diagnosis.lastEstablished > 0) ", " + ago(diagnosis.lastEstablished) else ""),
                        )
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        val dns = diagnosis.dns
                        InfoRow(stringResource(R.string.label_lookups), stringResource(R.string.lookups_value, dns.queries, dns.failed, dns.slow))
                        for (l in dns.recent.asReversed()) {
                            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                            InfoRow(
                                "${l.name} ${l.type}",
                                listOf(ago(l.at, alone = true), stringResource(R.string.lookup_ms, l.millis),
                                    l.why.ifEmpty { stringResource(R.string.lookup_slow) }).joinToString(" · "),
                            )
                        }
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    }
                    Text(
                        stringResource(R.string.diagnosis_about),
                        Modifier.padding(Space.l),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedButton(
                        { onCopyReport(); scope.launch { snackbar.showSnackbar(copied) } },
                        Modifier.fillMaxWidth().padding(start = Space.l, end = Space.l, bottom = Space.l),
                    ) { Text(stringResource(R.string.action_copy_log)) }
                }
            }
        }
    }
}

@Composable
private fun SwitchRow(title: String, about: String, checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .toggleable(checked, enabled = enabled, role = Role.Switch, onValueChange = onChange)
            .padding(horizontal = Space.l, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(about, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(Space.m))
        Switch(checked, null, enabled = enabled)
    }
}

@Composable
private fun relaysText(view: NetworkView): String {
    val d = view.details
    val parts = mutableListOf(pluralStringResource(R.plurals.relays_available, d.relays, d.relays))
    if (d.home.isNotEmpty()) parts += stringResource(R.string.relays_home, d.home)
    if (view.settings.httpsOnly) {
        parts += if (d.httpsRelays.isEmpty()) stringResource(R.string.relays_https_none)
        else stringResource(R.string.relays_https, d.httpsRelays.joinToString(", "))
    }
    return parts.joinToString(", ")
}

@Composable
private fun namesText(view: NetworkView): String {
    val n = view.names ?: return ""
    return when {
        !view.settings.names -> stringResource(R.string.names_off, n.domain)
        n.resolved -> stringResource(R.string.names_resolved, n.domain)
        else -> stringResource(R.string.names_not_resolved, n.domain)
    }
}

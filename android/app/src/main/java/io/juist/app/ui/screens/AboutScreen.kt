package io.juist.app.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.sp
import io.juist.app.R
import io.juist.app.ui.components.BackBar
import io.juist.app.ui.components.InfoRow
import io.juist.app.ui.components.Panel
import io.juist.app.ui.components.Readable
import io.juist.app.ui.components.SectionTitle
import io.juist.app.ui.components.Wordmark
import io.juist.app.ui.theme.PlexMono
import io.juist.app.ui.theme.Space
import kotlinx.coroutines.launch

/** The app's version, where its handbook is, its licenses, and its log for a bug report. */
@Composable
fun AboutScreen(
    version: String,
    onHandbook: () -> Unit,
    onLicenses: () -> Unit,
    onCopyLog: () -> Unit,
    onBack: () -> Unit,
) {
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val copied = stringResource(R.string.log_copied)
    Scaffold(
        topBar = { BackBar(stringResource(R.string.about_title), onBack) },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize()) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = Space.xxl)) {
                Column(Modifier.padding(Space.xl)) {
                    Wordmark()
                    Spacer(Modifier.height(Space.l))
                    Text(
                        stringResource(R.string.about_body),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Panel {
                    InfoRow(stringResource(R.string.label_version), version)
                }
                SectionTitle(stringResource(R.string.section_more))
                Panel {
                    TextButton(onHandbook, Modifier.padding(horizontal = Space.s)) { Text(stringResource(R.string.action_handbook)) }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    TextButton(onLicenses, Modifier.padding(horizontal = Space.s)) { Text(stringResource(R.string.action_licenses)) }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    TextButton(
                        { onCopyLog(); scope.launch { snackbar.showSnackbar(copied) } },
                        Modifier.padding(horizontal = Space.s),
                    ) { Text(stringResource(R.string.action_copy_log)) }
                }
                Text(
                    stringResource(R.string.about_log),
                    Modifier.padding(horizontal = Space.xl, vertical = Space.m),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** The licenses of everything the app is built from, as the build gathered them. */
@Composable
fun LicensesScreen(text: String, onBack: () -> Unit) {
    val lines = remember(text) { text.lines() }
    Scaffold(topBar = { BackBar(stringResource(R.string.action_licenses), onBack) }) { padding ->
        LazyColumn(Modifier.padding(padding).fillMaxSize()) {
            items(lines) { line ->
                Text(
                    line,
                    Modifier.padding(horizontal = Space.l),
                    style = TextStyle(fontFamily = PlexMono, fontSize = 11.sp, lineHeight = 15.sp),
                )
            }
        }
    }
}

package io.juist.app.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.expandVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.juist.app.R
import io.juist.app.core.JoinState
import io.juist.app.core.JoinStep
import io.juist.app.ui.components.BackBar
import io.juist.app.ui.components.Panel
import io.juist.app.ui.components.Readable
import io.juist.app.ui.theme.Motion
import io.juist.app.ui.theme.MonoWords
import io.juist.app.ui.theme.Space

/**
 * A join under way: how far it is, the words the admin compares, in large
 * type, and the votes the admission waits for.
 */
@Composable
fun JoiningScreen(state: JoinState, onCancel: () -> Unit, onRetry: () -> Unit, onScan: () -> Unit = {}) {
    Scaffold(topBar = { BackBar(stringResource(R.string.joining_title), onCancel) }) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize()) {
            Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                when (state) {
                    is JoinState.Failed -> Failure(state.message ?: stringResource(R.string.core_off), state.byCode)
                    is JoinState.Running -> Progress(state)
                    else -> Progress(JoinState.Running(JoinStep.Starting))
                }
            }
            Column(Modifier.fillMaxWidth().padding(horizontal = Space.xl, vertical = Space.l)) {
                if (state is JoinState.Failed && state.byCode) {
                    Button(onScan, Modifier.fillMaxWidth().heightIn(min = 56.dp)) { Text(stringResource(R.string.action_scan)) }
                    Spacer(Modifier.height(Space.s))
                    OutlinedButton(onRetry, Modifier.fillMaxWidth().heightIn(min = 56.dp)) { Text(stringResource(R.string.action_try_again)) }
                    Spacer(Modifier.height(Space.s))
                } else if (state is JoinState.Failed) {
                    Button(onRetry, Modifier.fillMaxWidth().heightIn(min = 56.dp)) { Text(stringResource(R.string.action_try_again)) }
                    Spacer(Modifier.height(Space.s))
                }
                OutlinedButton(onCancel, Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
                    Text(stringResource(if (state is JoinState.Failed) R.string.action_back else R.string.action_cancel))
                }
            }
        }
    }
}

@Composable
private fun Progress(s: JoinState.Running) {
    Spacer(Modifier.height(Space.l))
    Column(Modifier.padding(horizontal = Space.l), verticalArrangement = Arrangement.spacedBy(Space.xs)) {
        val reached = s.step >= JoinStep.Connected
        StepRow(
            stringResource(if (s.step == JoinStep.Meeting) R.string.join_meeting else R.string.join_looking),
            done = reached, active = !reached,
        )
        StepRow(
            stringResource(if (s.relayed) R.string.join_connected_relay else R.string.join_connected),
            done = s.step >= JoinStep.Compare, active = s.step == JoinStep.Connected, shown = reached,
        )
        StepRow(
            if (s.quorum > 0) pluralStringResource(R.plurals.join_votes, s.quorum, s.votes, s.quorum) else stringResource(R.string.join_approval),
            done = false, active = s.step >= JoinStep.Compare, shown = s.step >= JoinStep.Compare,
        )
    }
    AnimatedVisibility(s.words.isNotEmpty(), enter = fadeIn(tween(Motion.LONG)) + expandVertically(tween(Motion.LONG))) {
        Column {
            Spacer(Modifier.height(Space.xl))
            Words(s.words)
        }
    }
    if (s.quorum > 0) {
        Spacer(Modifier.height(Space.l))
        LinearProgressIndicator(
            progress = { s.votes.toFloat() / s.quorum },
            modifier = Modifier.fillMaxWidth().padding(horizontal = Space.xl),
        )
    }
}

@Composable
private fun StepRow(text: String, done: Boolean, active: Boolean, shown: Boolean = true) {
    if (!shown) return
    Row(
        Modifier.fillMaxWidth().padding(vertical = Space.s).semantics(mergeDescendants = true) {
            if (active) liveRegion = LiveRegionMode.Polite
        },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(24.dp), contentAlignment = Alignment.Center) {
            when {
                done -> Icon(Icons.Filled.Check, stringResource(R.string.done), tint = MaterialTheme.colorScheme.primary)
                active -> CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.5.dp)
            }
        }
        Spacer(Modifier.width(Space.m))
        Text(
            text,
            style = MaterialTheme.typography.bodyLarge,
            color = if (done || active) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** The four words, two to a line, as large as a glance across a table needs. */
@Composable
private fun Words(words: List<String>) {
    val spoken = words.joinToString(" ")
    Panel(color = MaterialTheme.colorScheme.primaryContainer) {
        Column(Modifier.fillMaxWidth().padding(Space.xl), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                stringResource(R.string.join_compare_title),
                Modifier.semantics { heading() },
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(Space.l))
            Column(
                Modifier.semantics(mergeDescendants = true) { contentDescription = spoken },
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                for (line in words.chunked(2)) {
                    Text(
                        line.joinToString("  "),
                        style = MonoWords,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        textAlign = TextAlign.Center,
                    )
                }
            }
            Spacer(Modifier.height(Space.l))
            Text(
                stringResource(R.string.join_compare_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun Failure(message: String, byCode: Boolean) {
    Column(Modifier.padding(Space.xl)) {
        Text(
            stringResource(R.string.join_failed), Modifier.semantics { heading() },
            style = MaterialTheme.typography.titleLarge,
        )
        Spacer(Modifier.height(Space.m))
        Text(
            stringResource(if (byCode) R.string.join_failed_code else R.string.join_failed_body),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (message.isNotEmpty()) {
            Spacer(Modifier.height(Space.l))
            Surface(shape = MaterialTheme.shapes.medium, color = MaterialTheme.colorScheme.errorContainer) {
                Text(
                    message,
                    Modifier.fillMaxWidth().padding(Space.l),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }
    }
}

package io.juist.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import io.juist.app.R
import io.juist.app.ui.components.Readable
import io.juist.app.ui.components.Wordmark
import io.juist.app.ui.theme.PlexMono
import io.juist.app.ui.theme.Space
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle

/** Where a device in no network starts: an invite scanned or typed. */
@Composable
fun WelcomeScreen(onScan: () -> Unit, onCode: () -> Unit, onAbout: () -> Unit) {
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Readable(Modifier.safeDrawingPadding()) {
            Column(
                Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = Space.xl),
            ) {
                Spacer(Modifier.height(Space.xxxl))
                Wordmark(height = 44.dp)
                Spacer(Modifier.height(Space.xxl))
                Text(
                    stringResource(R.string.welcome_title),
                    Modifier.semantics { heading() },
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Spacer(Modifier.height(Space.m))
                Text(
                    stringResource(R.string.welcome_body),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(Space.xl))
                Step(1, stringResource(R.string.welcome_step_invite))
                Step(2, stringResource(R.string.welcome_step_scan))
                Step(3, stringResource(R.string.welcome_step_words))
                Spacer(Modifier.height(Space.xl))
            }
            Column(
                Modifier.fillMaxWidth().padding(horizontal = Space.xl, vertical = Space.l),
                verticalArrangement = Arrangement.spacedBy(Space.m),
            ) {
                Button(onScan, Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
                    Icon(painterResource(R.drawable.ic_qr), null, Modifier.size(20.dp))
                    Spacer(Modifier.size(Space.s))
                    Text(stringResource(R.string.action_scan))
                }
                OutlinedButton(onCode, Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
                    Icon(painterResource(R.drawable.ic_keyboard), null, Modifier.size(20.dp))
                    Spacer(Modifier.size(Space.s))
                    Text(stringResource(R.string.action_enter_code))
                }
                TextButton(onAbout, Modifier.align(Alignment.CenterHorizontally)) {
                    Text(stringResource(R.string.about_title))
                }
            }
        }
    }
}

/** text with each juist command in it set in the monospace face, as the website sets commands. */
private fun commands(text: String) = buildAnnotatedString {
    var at = 0
    for (m in Regex("juist [a-z]+").findAll(text)) {
        append(text, at, m.range.first)
        withStyle(SpanStyle(fontFamily = PlexMono)) { append(m.value) }
        at = m.range.last + 1
    }
    append(text, at, text.length)
}

@Composable
private fun Step(n: Int, text: String) {
    Row(Modifier.padding(vertical = Space.s), verticalAlignment = Alignment.Top) {
        Surface(
            Modifier.size(28.dp),
            shape = MaterialTheme.shapes.extraLarge,
            color = MaterialTheme.colorScheme.primaryContainer,
        ) {
            Text(
                n.toString(),
                Modifier.padding(top = 3.dp),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            )
        }
        Spacer(Modifier.size(Space.m))
        Text(
            commands(text),
            Modifier.padding(top = 3.dp),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onBackground,
        )
    }
}

package io.juist.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.juist.app.R
import io.juist.app.core.CodeProblem
import io.juist.app.core.InviteCode
import io.juist.app.ui.components.BackBar
import io.juist.app.ui.components.Readable
import io.juist.app.ui.theme.MonoBody
import io.juist.app.ui.theme.PlexMono
import io.juist.app.ui.theme.Space
import io.juist.app.ui.LocalInviteChecks

/**
 * The invite typed: a number and three words, each word completed from the
 * list its place takes, or a link pasted whole. The field is a password field
 * to the keyboard, which then neither learns nor suggests it.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun CodeScreen(onInvite: (String) -> Unit, onBack: () -> Unit, initial: String = "", focus: Boolean = true) {
    var value by rememberSaveable(stateSaver = TextFieldValue.Saver) {
        mutableStateOf(TextFieldValue(initial, TextRange(initial.length)))
    }
    var tried by rememberSaveable { mutableStateOf(false) }
    val focusRequester = remember { FocusRequester() }
    LaunchedEffect(Unit) { if (focus) focusRequester.requestFocus() }

    val checks = LocalInviteChecks.current
    val text = value.text
    val link = InviteCode.isLink(text)
    val linkProblem = remember(text) { if (link) checks.linkProblem(text) else null }
    val problem = remember(text) { if (link) null else InviteCode.problem(checks, text) }
    val ready = if (link) linkProblem == null else problem == null
    val parts = InviteCode.parts(text)
    val typingLast = text.isNotEmpty() && !text.last().isWhitespace() && text.last() != '-'
    // What is wrong is said once a part is finished, or once Continue was tried.
    val shown: String? = when {
        link -> linkProblem?.let { stringResource(R.string.code_bad_link) }
        problem is CodeProblem.Number && (parts.size > 1 || tried) -> stringResource(R.string.code_bad_number)
        problem is CodeProblem.UnknownWord && (problem.word != parts.lastOrNull() || !typingLast || tried) ->
            stringResource(R.string.code_unknown_word, problem.word)
        problem is CodeProblem.WrongPlace && (problem.word != parts.lastOrNull() || !typingLast || tried) ->
            stringResource(R.string.code_wrong_place, problem.word)
        problem is CodeProblem.Incomplete && tried -> stringResource(R.string.code_incomplete)
        else -> null
    }
    val position = parts.size - 2 // of the word being typed, 0 after the number
    val suggestions = remember(text) {
        if (!link && typingLast && position in 0 until InviteCode.WORDS) {
            InviteCode.completions(checks, parts.last(), position).filter { it != parts.last() || position < InviteCode.WORDS - 1 }
        } else {
            emptyList()
        }
    }

    fun submit() {
        tried = true
        if (ready) onInvite(if (link) text.trim() else InviteCode.canonical(parts))
    }

    Scaffold(topBar = { BackBar(stringResource(R.string.code_title), onBack) }) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize().imePadding()) {
            Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = Space.xl)) {
                Spacer(Modifier.height(Space.l))
                Text(
                    stringResource(R.string.code_body),
                    style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(Space.xl))
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    modifier = Modifier.fillMaxWidth().focusRequester(focusRequester),
                    label = { Text(stringResource(R.string.code_label)) },
                    placeholder = { Text("42-drumbeat-tolerance-glucose", style = MonoBody) },
                    textStyle = MonoBody,
                    singleLine = !link,
                    isError = shown != null,
                    supportingText = {
                        Text(
                            shown ?: stringResource(if (link) R.string.code_link else R.string.code_supporting),
                            Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                        )
                    },
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.None,
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done,
                    ),
                    keyboardActions = KeyboardActions(onDone = { submit() }),
                )
                if (!link) {
                    Spacer(Modifier.height(Space.s))
                    Slots(parts, problem, typingLast)
                }
                if (suggestions.isNotEmpty()) {
                    Spacer(Modifier.height(Space.m))
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(Space.s)) {
                        for (word in suggestions) {
                            SuggestionChip(
                                onClick = {
                                    val done = parts.dropLast(1) + word
                                    val next = InviteCode.canonical(done) + if (done.size < 1 + InviteCode.WORDS) "-" else ""
                                    value = TextFieldValue(next, TextRange(next.length))
                                },
                                label = { Text(word, fontFamily = PlexMono) },
                            )
                        }
                    }
                }
            }
            Button(
                ::submit,
                Modifier.fillMaxWidth().padding(horizontal = Space.xl, vertical = Space.l).heightIn(min = 56.dp),
                enabled = text.isNotBlank(),
            ) { Text(stringResource(R.string.action_continue)) }
        }
    }
}

/** The four parts of a code, each marked as typed, valid or not yet. */
@Composable
private fun Slots(parts: List<String>, problem: CodeProblem?, typingLast: Boolean) {
    val bad = when (problem) {
        is CodeProblem.Number -> 0
        is CodeProblem.UnknownWord -> parts.indexOf(problem.word)
        is CodeProblem.WrongPlace -> parts.indexOf(problem.word)
        else -> -1
    }.takeUnless { typingLast && it == parts.lastIndex } ?: -1
    Row(horizontalArrangement = Arrangement.spacedBy(Space.xs)) {
        for (i in 0..InviteCode.WORDS) {
            val filled = i < parts.size
            val color = when {
                i == bad -> MaterialTheme.colorScheme.error
                filled && (bad < 0 || i < bad) -> MaterialTheme.colorScheme.primary
                else -> MaterialTheme.colorScheme.outlineVariant
            }
            Surface(Modifier.weight(if (i == 0) 0.6f else 1f).height(4.dp), shape = MaterialTheme.shapes.extraSmall, color = color) {}
        }
    }
    Text(
        stringResource(R.string.code_parts, parts.size.coerceAtMost(1 + InviteCode.WORDS), 1 + InviteCode.WORDS),
        Modifier.fillMaxWidth().padding(top = Space.xs),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.End,
    )
}

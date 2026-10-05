package io.juist.app.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import io.juist.app.R
import io.juist.app.core.InviteCode
import io.juist.app.ui.components.BackBar
import io.juist.app.ui.components.Panel
import io.juist.app.ui.components.Readable
import io.juist.app.ui.theme.MonoBody
import io.juist.app.ui.theme.Space

/** The longest member name the app suggests; the log takes longer ones. */
private const val MAX_NAME = 63

/** A member name from a phone's own name: "Pixel 8 Pro" becomes "pixel-8-pro". */
fun suggestedName(deviceName: String?): String {
    val name = deviceName.orEmpty().lowercase()
        .replace(Regex("[^a-z0-9]+"), "-").trim('-').take(MAX_NAME).trim('-')
    return name.ifEmpty { "phone" }
}

fun validName(name: String) = name.isNotBlank() && name.length <= MAX_NAME && name.none { it.isISOControl() }

/** The invite and the name to ask for, and what joining will do, before it does. */
@Composable
fun ConfirmScreen(
    invite: String,
    suggested: String,
    onJoin: (name: String) -> Unit,
    onBack: () -> Unit,
    fromElsewhere: Boolean = false,
) {
    var name by rememberSaveable { mutableStateOf(suggested) }
    val ok = validName(name.trim())
    val link = InviteCode.isLink(invite)
    Scaffold(topBar = { BackBar(stringResource(R.string.confirm_title), onBack) }) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize().imePadding()) {
            Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                Spacer(Modifier.height(Space.l))
                Panel {
                    Row(Modifier.padding(Space.l), verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            painterResource(if (link) R.drawable.ic_qr else R.drawable.ic_keyboard), null,
                            Modifier.size(24.dp), tint = MaterialTheme.colorScheme.primary,
                        )
                        Spacer(Modifier.size(Space.m))
                        Column {
                            Text(
                                stringResource(if (link) R.string.confirm_link else R.string.confirm_code),
                                style = MaterialTheme.typography.titleSmall,
                            )
                            Text(
                                when {
                                    fromElsewhere -> stringResource(R.string.confirm_link_opened)
                                    link -> stringResource(R.string.confirm_link_about)
                                    else -> invite
                                },
                                style = if (link) MaterialTheme.typography.bodyMedium else MonoBody,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                Spacer(Modifier.height(Space.xl))
                Column(Modifier.padding(horizontal = Space.l)) {
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it.take(MAX_NAME) },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(stringResource(R.string.confirm_name)) },
                        supportingText = { Text(stringResource(R.string.confirm_name_about)) },
                        singleLine = true,
                        isError = !ok,
                        keyboardOptions = KeyboardOptions(
                            capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, imeAction = ImeAction.Go,
                        ),
                        keyboardActions = KeyboardActions(onGo = { if (ok) onJoin(name.trim()) }),
                    )
                }
                Spacer(Modifier.height(Space.l))
                Row(Modifier.padding(horizontal = Space.l)) {
                    Icon(Icons.Outlined.Info, null, Modifier.size(20.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.size(Space.m))
                    Text(
                        stringResource(R.string.confirm_vpn_about),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Button(
                { onJoin(name.trim()) },
                Modifier.fillMaxWidth().padding(horizontal = Space.xl, vertical = Space.l).heightIn(min = 56.dp),
                enabled = ok,
            ) { Text(stringResource(R.string.action_join)) }
        }
    }
}

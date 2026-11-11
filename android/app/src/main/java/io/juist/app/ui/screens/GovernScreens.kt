package io.juist.app.ui.screens

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.activity.compose.BackHandler
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.foundation.selection.toggleable
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import io.juist.app.R
import io.juist.app.core.InviteState
import io.juist.app.ui.components.Address
import io.juist.app.ui.components.BackBar
import io.juist.app.ui.components.Panel
import io.juist.app.ui.components.Readable
import io.juist.app.ui.components.SectionTitle
import io.juist.app.ui.theme.MonoBody
import io.juist.app.ui.theme.Space

/** The names a network and a device may have, as `juist create` takes them. */
private val nameRule = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

internal fun checkedName(s: String) = nameRule.matches(s)

/**
 * Founds a network with this phone in it: its name and the phone's. The
 * phone's screen lock or biometric guards the admin key it creates.
 */
@Composable
fun CreateScreen(suggested: String, busy: Boolean, onCreate: (network: String, name: String) -> Unit, onBack: () -> Unit) {
    var network by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf(suggested) }
    Scaffold(topBar = { BackBar(stringResource(R.string.create_title), onBack) }, containerColor = MaterialTheme.colorScheme.background) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize()) {
            Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = Space.xl)) {
                Text(stringResource(R.string.create_body), style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(Space.xl))
                OutlinedTextField(network, { network = it.trim() }, Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.create_network)) }, singleLine = true,
                    isError = network.isNotEmpty() && !checkedName(network),
                    supportingText = { Text(stringResource(R.string.name_rule)) })
                Spacer(Modifier.height(Space.m))
                OutlinedTextField(name, { name = it.trim() }, Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.create_device)) }, singleLine = true,
                    isError = name.isNotEmpty() && !checkedName(name))
                Spacer(Modifier.height(Space.l))
                Text(stringResource(R.string.create_admin_key), style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(Space.m))
                Text(stringResource(R.string.create_public_derp), style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Button(
                { onCreate(network, name) },
                Modifier.fillMaxWidth().padding(horizontal = Space.xl, vertical = Space.l).heightIn(min = 56.dp),
                enabled = !busy && checkedName(network) && checkedName(name),
            ) {
                if (busy) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                else Text(stringResource(R.string.action_create))
            }
        }
    }
}

/**
 * The admin key's backup, offered and never required: every copy is one
 * more place the key can be taken from. With breakGlass, the network was
 * just founded, and its break-glass secret is shown this one time.
 */
@Composable
fun BackupScreen(
    breakGlass: String?,
    onCopyBreakGlass: () -> Unit,
    onCopyLine: () -> Unit,
    onSaveFile: (password: String) -> Unit,
    onDone: () -> Unit,
) {
    // Not saveable: a password stays out of the saved state.
    var password by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    // Going back by mistake would lose the break-glass secret, shown only
    // now: back asks first until it is copied. Done is meant.
    var copied by remember { mutableStateOf(false) }
    var asking by remember { mutableStateOf(false) }
    val back = { if (breakGlass != null && !copied) asking = true else onDone() }
    BackHandler(breakGlass != null && !copied) { asking = true }
    if (asking) {
        AlertDialog(
            onDismissRequest = { asking = false },
            text = { Text(stringResource(R.string.backup_leave_body)) },
            confirmButton = { TextButton({ asking = false; onDone() }) { Text(stringResource(R.string.backup_leave)) } },
            dismissButton = { TextButton({ asking = false }) { Text(stringResource(R.string.backup_stay)) } },
        )
    }
    Scaffold(topBar = { BackBar(stringResource(R.string.backup_title), back) }, containerColor = MaterialTheme.colorScheme.background) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize()) {
            Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(bottom = Space.xl)) {
                if (breakGlass != null) {
                    SectionTitle(stringResource(R.string.backup_break_glass))
                    Panel {
                        Text(stringResource(R.string.backup_break_glass_body), Modifier.padding(Space.l),
                            style = MaterialTheme.typography.bodyMedium)
                        Address(breakGlass, Modifier.padding(horizontal = Space.l))
                        TextButton({ copied = true; onCopyBreakGlass() }, Modifier.padding(Space.s)) {
                            Text(stringResource(R.string.action_copy))
                        }
                    }
                }
                SectionTitle(stringResource(R.string.backup_admin_key))
                Panel {
                    Text(stringResource(R.string.backup_admin_key_body), Modifier.padding(Space.l), style = MaterialTheme.typography.bodyMedium)
                    OutlinedButton(onCopyLine, Modifier.fillMaxWidth().padding(horizontal = Space.l)) {
                        Text(stringResource(R.string.backup_copy_line))
                    }
                    Spacer(Modifier.height(Space.l))
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    Column(Modifier.padding(Space.l), verticalArrangement = Arrangement.spacedBy(Space.s)) {
                        Text(stringResource(R.string.backup_file_body), style = MaterialTheme.typography.bodyMedium)
                        OutlinedTextField(password, { password = it }, Modifier.fillMaxWidth(), singleLine = true,
                            label = { Text(stringResource(R.string.backup_password)) },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            supportingText = { Text(stringResource(R.string.backup_password_rule, MIN_PASSWORD)) })
                        OutlinedTextField(again, { again = it }, Modifier.fillMaxWidth(), singleLine = true,
                            label = { Text(stringResource(R.string.backup_password_again)) },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            isError = again.isNotEmpty() && again != password)
                        OutlinedButton({ onSaveFile(password) }, Modifier.fillMaxWidth(),
                            enabled = password.codePointCount(0, password.length) >= MIN_PASSWORD && again == password) {
                            Text(stringResource(R.string.backup_save_file))
                        }
                    }
                }
            }
            Button(onDone, Modifier.fillMaxWidth().padding(horizontal = Space.xl, vertical = Space.l).heightIn(min = 56.dp)) {
                Text(stringResource(R.string.action_done))
            }
        }
    }
}

/** The shortest password a backup file takes, as the core's. */
const val MIN_PASSWORD = 12

/**
 * An invite the phone offers: its QR code and code, then the words a joining
 * device shows, which the person compares before the admin key admits it.
 */
@Composable
fun InviteScreen(
    state: InviteState,
    onShare: (String) -> Unit,
    onSame: () -> Unit,
    onDifferent: () -> Unit,
    onClose: () -> Unit,
) {
    Scaffold(topBar = { BackBar(stringResource(R.string.invite_title), onClose) }, containerColor = MaterialTheme.colorScheme.background) { padding ->
        Readable(Modifier.padding(padding).fillMaxSize()) {
            Column(
                Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = Space.xl),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                when (state) {
                    InviteState.Idle, InviteState.Starting -> CircularProgressIndicator(Modifier.padding(Space.xxl))
                    is InviteState.Offered -> {
                        Text(stringResource(if (state.noLan) R.string.invite_scan_no_lan else R.string.invite_scan),
                            style = MaterialTheme.typography.bodyLarge)
                        Spacer(Modifier.height(Space.l))
                        Qr(state.link)
                        Spacer(Modifier.height(Space.l))
                        Text(stringResource(R.string.invite_code_label), style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(state.code, style = MonoBody)
                        Spacer(Modifier.height(Space.m))
                        OutlinedButton({ onShare(state.link) }) { Text(stringResource(R.string.invite_share_link)) }
                    }
                    is InviteState.Comparing -> {
                        Text(stringResource(R.string.invite_compare, state.name), style = MaterialTheme.typography.bodyLarge)
                        Spacer(Modifier.height(Space.l))
                        Panel(Modifier.fillMaxWidth()) {
                            Text(state.words, Modifier.padding(Space.xl).align(Alignment.CenterHorizontally),
                                style = MaterialTheme.typography.headlineSmall)
                        }
                    }
                    is InviteState.Admitting -> {
                        CircularProgressIndicator(Modifier.padding(Space.xxl))
                        Text(stringResource(R.string.invite_admitting, state.name))
                    }
                    is InviteState.Joined -> Text(stringResource(R.string.invite_joined, state.name),
                        style = MaterialTheme.typography.headlineSmall)
                    is InviteState.Ended -> Text(
                        when {
                            state.refused -> stringResource(R.string.invite_refused)
                            else -> state.why ?: stringResource(R.string.invite_ended)
                        },
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }
            if (state is InviteState.Comparing) {
                Row(Modifier.fillMaxWidth().padding(horizontal = Space.xl, vertical = Space.l),
                    horizontalArrangement = Arrangement.spacedBy(Space.m)) {
                    OutlinedButton(onDifferent, Modifier.weight(1f).heightIn(min = 56.dp)) { Text(stringResource(R.string.invite_different)) }
                    Button(onSame, Modifier.weight(1f).heightIn(min = 56.dp)) { Text(stringResource(R.string.invite_same)) }
                }
            }
        }
    }
}

/**
 * text as a QR code, dark on white whatever the theme, as scanners read best:
 * one pixel per module, scaled up unfiltered, since drawing it pixel by pixel
 * held the screen for seconds.
 */
@Composable
private fun Qr(text: String) {
    val bitmap = remember(text) {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0)
        val pixels = IntArray(m.width * m.height) { i ->
            if (m.get(i % m.width, i / m.width)) android.graphics.Color.BLACK else android.graphics.Color.WHITE
        }
        Bitmap.createBitmap(pixels, m.width, m.height, Bitmap.Config.ARGB_8888)
    }
    Image(
        bitmap.asImageBitmap(), stringResource(R.string.invite_qr),
        Modifier.size(260.dp).background(Color.White), filterQuality = FilterQuality.None,
    )
}

/** The roles an admin grants from the app, by the core's names. */
val appRoles = listOf("relay", "voucher", "exit")

/**
 * What the phone's admin key does to a member: its roles, and removing it.
 * Each change asks for the phone's biometric or screen lock first.
 */
@Composable
fun AdminSection(
    roles: Set<String>,
    isSelf: Boolean,
    enabled: Boolean,
    onRole: (String, Boolean) -> Unit,
    onRemove: () -> Unit,
    lastVoucher: Boolean = false,
) {
    var confirm by remember { mutableStateOf(false) }
    var revokeVoucher by remember { mutableStateOf(false) }
    SectionTitle(stringResource(R.string.section_admin))
    Panel {
        // A phone neither relays nor carries the internet for others.
        appRoles.filter { !isSelf || it == "voucher" }.forEachIndexed { i, role ->
            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            val on = role in roles
            Row(
                Modifier.fillMaxWidth()
                    .toggleable(on, enabled = enabled, role = Role.Switch) {
                        if (role == "voucher" && !it && lastVoucher) revokeVoucher = true else onRole(role, it)
                    }
                    .padding(horizontal = Space.l, vertical = Space.m),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(roleTitle(role), style = MaterialTheme.typography.titleMedium)
                    Text(roleAbout(role), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Switch(on, null, enabled = enabled)
            }
        }
        if (!isSelf) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            TextButton({ confirm = true }, Modifier.padding(Space.s), enabled = enabled) {
                Text(stringResource(R.string.action_remove_device), color = MaterialTheme.colorScheme.error)
            }
        }
    }
    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text(stringResource(R.string.remove_title)) },
            text = {
                Text(stringResource(R.string.remove_body) +
                    if (lastVoucher) "\n\n" + stringResource(R.string.last_voucher_body) else "")
            },
            confirmButton = { TextButton({ confirm = false; onRemove() }) { Text(stringResource(R.string.action_remove_device)) } },
            dismissButton = { TextButton({ confirm = false }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }
    if (revokeVoucher) {
        AlertDialog(
            onDismissRequest = { revokeVoucher = false },
            title = { Text(stringResource(R.string.last_voucher_title)) },
            text = { Text(stringResource(R.string.last_voucher_body)) },
            confirmButton = { TextButton({ revokeVoucher = false; onRole("voucher", false) }) { Text(stringResource(R.string.action_revoke)) } },
            dismissButton = { TextButton({ revokeVoucher = false }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }
}

@Composable
private fun roleTitle(role: String) = stringResource(
    when (role) {
        "relay" -> R.string.role_relay
        "voucher" -> R.string.role_voucher
        else -> R.string.role_exit
    },
)

@Composable
private fun roleAbout(role: String) = stringResource(
    when (role) {
        "relay" -> R.string.role_relay_about
        "voucher" -> R.string.role_voucher_about
        else -> R.string.role_exit_about
    },
)

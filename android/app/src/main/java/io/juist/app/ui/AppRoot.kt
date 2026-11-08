package io.juist.app.ui

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.PersistableBundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableStateSetOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import io.juist.app.BuildConfig
import io.juist.app.R
import io.juist.app.core.Connection
import io.juist.app.core.CoreOff
import io.juist.app.core.Report
import io.juist.app.core.JoinState
import io.juist.app.core.Juist
import io.juist.app.core.MAX_NETWORKS
import io.juist.app.core.NetworkView
import io.juist.app.core.networks
import io.juist.app.core.view
import io.juist.app.ui.screens.AboutScreen
import io.juist.app.ui.screens.CodeScreen
import io.juist.app.ui.screens.ConfirmScreen
import io.juist.app.ui.screens.DetailsScreen
import io.juist.app.ui.screens.JoiningScreen
import io.juist.app.ui.screens.LicensesScreen
import io.juist.app.ui.screens.MemberScreen
import io.juist.app.ui.screens.NetworksScreen
import io.juist.app.ui.screens.PingResult
import io.juist.app.ui.screens.ScanRoute
import io.juist.app.ui.screens.StatusScreen
import io.juist.app.ui.screens.WelcomeScreen
import io.juist.app.ui.screens.suggestedName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Where the app is: a stack of screens, kept across a recreated activity. */
sealed interface Route {
    data object Welcome : Route
    /** The welcome of a phone in a network already, which joins another. */
    data object Another : Route
    data object Networks : Route
    data object Scan : Route
    data object Code : Route
    data class Confirm(val invite: String, val fromElsewhere: Boolean = false) : Route
    data object Joining : Route
    data class Status(val slot: Int = 0) : Route
    data class MemberOf(val identity: String, val slot: Int = 0) : Route
    data object About : Route
    data object Licenses : Route
    data class Details(val slot: Int = 0) : Route

    val depth get() = when (this) {
        Welcome, Networks -> 0
        is Status, Another -> 1
        Scan, Code, About, is Details, is MemberOf -> 2
        is Confirm, Licenses -> 3
        Joining -> 4
    }
}

internal fun encode(r: Route): String = when (r) {
    is Route.Confirm -> (if (r.fromElsewhere) "opened:" else "confirm:") + r.invite
    is Route.MemberOf -> "member:${r.slot}:" + r.identity
    is Route.Status -> "status:${r.slot}"
    is Route.Details -> "details:${r.slot}"
    else -> r.toString()
}

/** The slot a saved route names before its colon, and the rest; slot 0 where it names none, as earlier apps saved it. */
private fun slotted(s: String): Pair<Int, String> {
    val n = s.substringBefore(':', "")
    return n.toIntOrNull()?.let { it to s.substringAfter(':') } ?: (0 to s)
}

internal fun decode(s: String): Route = when {
    s.startsWith("confirm:") -> Route.Confirm(s.removePrefix("confirm:"))
    s.startsWith("opened:") -> Route.Confirm(s.removePrefix("opened:"), fromElsewhere = true)
    s.startsWith("member:") -> slotted(s.removePrefix("member:")).let { (slot, id) -> Route.MemberOf(id, slot) }
    s.startsWith("status:") -> Route.Status(s.removePrefix("status:").toIntOrNull() ?: 0)
    s.startsWith("details:") -> Route.Details(s.removePrefix("details:").toIntOrNull() ?: 0)
    s == "Status" -> Route.Status(0)
    s == "Details" -> Route.Details(0)
    else -> listOf(Route.Welcome, Route.Another, Route.Networks, Route.Scan, Route.Code, Route.Joining, Route.About, Route.Licenses)
        .firstOrNull { it.toString() == s } ?: Route.Welcome
}

/** The screen a phone in networks starts at: the welcome in none, the network's status in one, the list in more. */
internal fun homeOf(networks: List<NetworkView>): Route = when (networks.size) {
    0 -> Route.Welcome
    1 -> Route.Status(networks[0].slot)
    else -> Route.Networks
}

private val stackSaver = listSaver<List<Route>, String>({ it.map(::encode) }, { it.map(::decode) })

@Composable
fun AppRoot(opened: MutableState<String?> = remember { mutableStateOf(null) }) {
    val context = LocalContext.current
    val connection by Juist.connection.collectAsStateWithLifecycle()
    val join by Juist.join.collectAsStateWithLifecycle()
    val pace by Juist.pace.collectAsStateWithLifecycle()
    val networks = connection.networks
    val inNetwork = networks.isNotEmpty()
    val home = homeOf(networks)
    var stack by rememberSaveable(stateSaver = stackSaver) { mutableStateOf(listOf(home)) }
    fun push(r: Route) { stack = stack + r }
    fun pop() { if (stack.size > 1) stack = stack.dropLast(1) }
    // Where a join starts: the welcome, or for another network the networks and the welcome beside them.
    val joinBase = if (inNetwork) listOf(home, Route.Another) else listOf(Route.Welcome)
    val canJoinAnother = inNetwork && networks.size < MAX_NETWORKS
    val most = stringResource(R.string.networks_most, MAX_NETWORKS)

    // The networks decide where home is: joined, removed, left and forgotten move it.
    LaunchedEffect(home, join) {
        when {
            join is JoinState.Joined -> {
                val slot = (join as JoinState.Joined).slot
                stack = if (home == Route.Networks) listOf(Route.Networks, Route.Status(slot)) else listOf(home)
                Juist.clearJoin()
            }
            join is JoinState.Running -> {}
            // Nothing joins any more, as after the process was restarted.
            join is JoinState.Idle && stack.last() == Route.Joining -> pop()
            stack.first() != home && (inNetwork || connection is Connection.On) -> stack = listOf(home)
        }
    }
    // A link opened from elsewhere goes to the join screen, where nothing happens without a tap.
    LaunchedEffect(opened.value, inNetwork) {
        val link = opened.value ?: return@LaunchedEffect
        opened.value = null
        if (join is JoinState.Running) return@LaunchedEffect
        if (!inNetwork) {
            stack = listOf(Route.Welcome, Route.Confirm(link, fromElsewhere = true))
        } else if (canJoinAnother) {
            stack = listOf(home, Route.Another, Route.Confirm(link, fromElsewhere = true))
        } else {
            toast(context, most)
        }
    }
    BackHandler(stack.size > 1) {
        if (stack.last() == Route.Joining) Juist.cancelJoin()
        pop()
    }

    // A VPN needs the person's consent once, and the notification is asked for alongside.
    var afterConsent by remember { mutableStateOf<(() -> Unit)?>(null) }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) afterConsent?.invoke()
        else Toast.makeText(context, R.string.vpn_refused, Toast.LENGTH_LONG).show()
        afterConsent = null
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    // The notification is asked for after the VPN, one dialog at a time.
    fun withVpn(then: () -> Unit) {
        val next = {
            then()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) {
                notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        val intent = Juist.consentIntent(context)
        if (intent == null) next() else {
            afterConsent = next
            consent.launch(intent)
        }
    }

    val pings = remember { mutableStateMapOf<String, List<PingResult>>() }
    val pinging = remember { mutableStateSetOf<String>() }
    val deviceName = remember { Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME) }
    // Relative times count from a clock that moves while the app is seen.
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val now by produceState(System.currentTimeMillis() / 1000) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                value = System.currentTimeMillis() / 1000
                delay(30_000)
            }
        }
    }
    val scope = rememberCoroutineScope()
    val handbook = stringResource(R.string.handbook_url)
    // Each screen in the stack keeps what was typed into it while another is on top.
    val saved = rememberSaveableStateHolder()

    CompositionLocalProvider(LocalNow provides now) { AnimatedContent(
        targetState = stack.last(),
        transitionSpec = {
            val forward = targetState.depth >= initialState.depth
            val dir = if (forward) 1 else -1
            (slideInHorizontally(tween(300)) { it / 6 * dir } + fadeIn(tween(300))) togetherWith
                (slideOutHorizontally(tween(300)) { -it / 6 * dir } + fadeOut(tween(200)))
        },
        label = "route",
    ) { route -> saved.SaveableStateProvider(encode(route)) {
        when (route) {
            Route.Welcome -> WelcomeScreen(onScan = { push(Route.Scan) }, onCode = { push(Route.Code) }, onAbout = { push(Route.About) })
            Route.Another -> WelcomeScreen(onScan = { push(Route.Scan) }, onCode = { push(Route.Code) }, onAbout = { push(Route.About) },
                onBack = ::pop)
            Route.Networks -> NetworksScreen(
                connection = connection,
                onConnect = { withVpn { Juist.connect(context) } },
                onDisconnect = { Juist.disconnect(context) },
                onNetwork = { push(Route.Status(it)) },
                onJoinAnother = { push(Route.Another) },
                onAbout = { push(Route.About) },
                onStartOver = { Juist.startOver(context) },
                saving = pace.powerSave,
            )
            Route.Scan -> ScanRoute(
                onInvite = { stack = stack.dropLast(1) + Route.Confirm(it) },
                onCode = { stack = stack.dropLast(1) + Route.Code },
                onBack = ::pop,
            )
            Route.Code -> CodeScreen(onInvite = { push(Route.Confirm(it)) }, onBack = ::pop)
            is Route.Confirm -> ConfirmScreen(
                invite = route.invite,
                fromElsewhere = route.fromElsewhere,
                suggested = suggestedName(deviceName),
                onJoin = { name ->
                    withVpn {
                        if (stack.last() == route && Juist.join(context, route.invite, name)) push(Route.Joining)
                    }
                },
                onBack = ::pop,
            )
            Route.Joining -> JoiningScreen(
                state = join,
                onCancel = {
                    Juist.cancelJoin()
                    pop()
                },
                onRetry = {
                    Juist.clearJoin()
                    pop()
                },
                onScan = {
                    Juist.clearJoin()
                    stack = joinBase + Route.Scan
                },
            )
            is Route.Status -> {
                val slot = route.slot
                // A network left or forgotten beside others leaves its screen.
                if (stack.size > 1 && connection.view(slot)?.inNetwork != true) LaunchedEffect(Unit) { pop() }
                StatusScreen(
                    connection = connection,
                    onConnect = { withVpn { Juist.connect(context) } },
                    onDisconnect = { Juist.disconnect(context) },
                    onMember = { push(Route.MemberOf(it.identity, slot)) },
                    onAbout = { push(Route.About) },
                    onDetails = { push(Route.Details(slot)) },
                    // A device in no network has nothing to keep a VPN on for.
                    onForget = {
                        scope.launch {
                            Juist.forget(slot).fold({ if (Juist.connection.value.networks.isEmpty()) Juist.disconnect(context) },
                                { toast(context, errorText(context, it)) })
                        }
                    },
                    onStartOver = { Juist.startOver(context) },
                    onExit = { id ->
                        scope.launch {
                            Juist.useExit(slot, id).onFailure { toast(context, errorText(context, it)) }
                        }
                    },
                    onVpnSettings = { runCatching { context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) } },
                    saving = pace.powerSave,
                    slot = slot,
                    onJoinAnother = if (canJoinAnother) ({ push(Route.Another) }) else null,
                    onLeave = {
                        scope.launch {
                            Juist.leave(slot).fold({ if (Juist.connection.value.networks.isEmpty()) Juist.disconnect(context) },
                                { toast(context, errorText(context, it)) })
                        }
                    },
                    onBack = if (stack.size > 1) ::pop else null,
                )
            }
            is Route.MemberOf -> {
                val view = connection.view(route.slot)
                val member = (if (view?.self?.identity == route.identity) view.self else null)
                    ?: view?.members?.firstOrNull { it.identity == route.identity }
                if (member == null) {
                    LaunchedEffect(Unit) { pop() }
                } else {
                    MemberScreen(
                        member = member,
                        on = connection is Connection.On,
                        pings = pings[member.identity].orEmpty(),
                        pinging = member.identity in pinging,
                        onPing = {
                            pinging += member.identity
                            scope.launch {
                                val r = Juist.ping(route.slot, member.identity).fold(
                                    { PingResult(it) },
                                    { PingResult(null, errorText(context, it)) },
                                )
                                pings[member.identity] = (listOf(r) + pings[member.identity].orEmpty()).take(5)
                                pinging -= member.identity
                            }
                        },
                        onOpen = { open(context, it) },
                        onBack = ::pop,
                    )
                }
            }
            Route.About -> AboutScreen(
                version = BuildConfig.VERSION_NAME,
                onHandbook = { open(context, handbook) },
                onLicenses = { push(Route.Licenses) },
                onCopyLog = { copyPrivately(context, Report.text(context, BuildConfig.VERSION_NAME)) },
                onBack = ::pop,
            )
            is Route.Details -> {
                val slot = route.slot
                val view = connection.view(slot)
                if (view == null) {
                    LaunchedEffect(Unit) { pop() }
                } else {
                    val on = connection is Connection.On
                    val changes by produceState<List<io.juist.app.core.Change>?>(null, on, slot) {
                        value = if (on) Juist.changes(slot).getOrNull() else null
                    }
                    val diagnosis by produceState(Juist.diagnosis(), connection) { value = Juist.diagnosis() }
                    DetailsScreen(
                        view = view,
                        on = on,
                        changes = changes,
                        diagnosis = diagnosis,
                        onNames = { v -> scope.launch { Juist.setNames(slot, v).onFailure { toast(context, errorText(context, it)) } } },
                        onHttpsOnly = { v -> scope.launch { Juist.setHttpsOnly(slot, v).onFailure { toast(context, errorText(context, it)) } } },
                        onCopyReport = { copyPrivately(context, Report.text(context, BuildConfig.VERSION_NAME)) },
                        onBack = ::pop,
                    )
                }
            }
            Route.Licenses -> {
                val text by produceState("") {
                    value = withContext(Dispatchers.IO) {
                        runCatching { context.assets.open("licenses.txt").bufferedReader().use { it.readText() } }.getOrDefault("")
                    }
                }
                LicensesScreen(text = text, onBack = ::pop)
            }
        }
    } } }
    // A screen taken off the stack starts afresh when it is opened again.
    var shown by remember { mutableStateOf(setOf<String>()) }
    LaunchedEffect(stack) {
        val kept = stack.map(::encode).toSet()
        (shown - kept).forEach(saved::removeState)
        shown = kept
    }
}

private fun open(context: Context, url: String) {
    runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, url.toUri())) }
        .onFailure { Toast.makeText(context, R.string.no_browser, Toast.LENGTH_SHORT).show() }
}

/** Copies text kept from the clipboard's preview and history, as the log naming the network's devices. */
private fun copyPrivately(context: Context, text: String) {
    val clip = ClipData.newPlainText("juist", text)
    clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
}

private fun toast(context: Context, text: String) = Toast.makeText(context, text, Toast.LENGTH_LONG).show()

/** What went wrong in a call into the core, in the app's words where they are its own. */
fun errorText(context: Context, t: Throwable): String =
    if (t is CoreOff) context.getString(R.string.core_off) else t.message.orEmpty()

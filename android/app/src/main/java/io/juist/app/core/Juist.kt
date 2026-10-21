package io.juist.app.core

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.edit
import io.juist.mobile.Core
import io.juist.mobile.JoinListener
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** Whether the core runs, and what it last said. */
sealed interface Connection {
    /** The VPN is off; [last] is what the core said before it stopped, if it ever ran. */
    data class Off(val last: NetworkView?, val reason: OffReason = OffReason.None) : Connection

    data class Starting(val last: NetworkView?) : Connection

    data class On(val view: NetworkView) : Connection

    /** The core did not start; [message] is its own reason, in English. */
    data class Failed(val message: String, val last: NetworkView?) : Connection
}

enum class OffReason { None, Revoked }

/** How a join goes, as the core reports it (internal/guest's events). */
sealed interface JoinState {
    data object Idle : JoinState

    data class Running(val step: JoinStep, val relayed: Boolean = false, val words: List<String> = emptyList(),
        val votes: Int = 0, val quorum: Int = 0) : JoinState

    data object Joined : JoinState

    /**
     * The join failed, by a code where [byCode], which only finds its host on
     * the LAN; [message] is the core's reason, null where juist stopped.
     */
    data class Failed(val message: String?, val byCode: Boolean = false) : JoinState
}

enum class JoinStep { Starting, Looking, Meeting, Connected, Compare, Waiting }

/** A call into the core while none runs. */
class CoreOff : IllegalStateException("juist is off")

/** What the core last said, whether it runs or not. */
val Connection.lastView: NetworkView?
    get() = when (this) {
        is Connection.On -> view
        is Connection.Off -> last
        is Connection.Starting -> last
        is Connection.Failed -> last
    }

/** What [Juist] asks of a running core: the Go core's, or a test's. */
internal interface CoreCalls {
    fun status(): String
    /** Joins by invite as name, telling progress each event (internal/guest.EventKind). */
    fun join(invite: String, name: String, progress: (kind: Int, text: String, votes: Int, quorum: Int) -> Unit)
    fun cancelJoin()
    /** One echo's round trip, in microseconds. */
    fun ping(identity: String): Long
    fun useExit(identity: String)
    fun exitOff()
    fun forget()
}

/** The Go core's calls. */
internal class GoCore(private val c: Core) : CoreCalls {
    override fun status(): String = c.status()
    override fun join(invite: String, name: String, progress: (Int, String, Int, Int) -> Unit) =
        c.join(invite, name, JoinListener { kind, text, votes, quorum -> progress(kind, text, votes, quorum) })
    override fun cancelJoin() = c.cancelJoin()
    override fun ping(identity: String): Long = c.ping(identity)
    override fun useExit(identity: String) = c.useExit(identity)
    override fun exitOff() = c.exitOff()
    override fun forget() = c.forget()
}

/** The process's one core, which [JuistVpnService] runs and the screens watch. */
object Juist {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var cacheFile: File

    private val _connection = MutableStateFlow<Connection>(Connection.Off(null))
    val connection: StateFlow<Connection> = _connection.asStateFlow()

    private val _join = MutableStateFlow<JoinState>(JoinState.Idle)
    val join: StateFlow<JoinState> = _join.asStateFlow()

    @Volatile private var core: CoreCalls? = null
    private var poller: Job? = null
    // Held while the connection is published, so that no status outlives the core it came from.
    private val publishing = Any()
    private var joinJob: Job? = null

    private val _visible = MutableStateFlow(false)
    /** Whether a screen is showing, which makes the status poll fast and keeps the pace on a metered network. */
    val shown: StateFlow<Boolean> = _visible.asStateFlow()
    var visible: Boolean
        get() = _visible.value
        set(v) { _visible.value = v }

    private val _pace = MutableStateFlow(Pace())
    /** The phone's pace as [JuistVpnService] last read it; the screen off pauses the status poll. */
    val pace: StateFlow<Pace> = _pace.asStateFlow()

    internal fun paced(p: Pace) {
        _pace.value = p
    }

    fun init(context: Context) {
        cacheFile = File(context.noBackupFilesDir, "last-status.json")
        val last = runCatching { parseView(cacheFile.readText()) }.getOrNull()
        _connection.value = Connection.Off(last)
    }

    /** The state directory, kept from backups and transfers. */
    fun home(context: Context) = File(context.noBackupFilesDir, "juist")

    val last: NetworkView? get() = _connection.value.lastView

    /** Whether Android must first ask the user to let juist set up a VPN. */
    fun consentIntent(context: Context): Intent? = VpnService.prepare(context)

    private fun prefs(context: Context) = context.getSharedPreferences("juist", Context.MODE_PRIVATE)

    /** Whether the person last left the VPN on, so that a reboot or an update turns it on again. */
    fun wanted(context: Context) = prefs(context).getBoolean("wanted", false)

    internal fun want(context: Context, on: Boolean) = prefs(context).edit { putBoolean("wanted", on) }

    fun connect(context: Context) {
        want(context, true)
        _connection.update { if (it is Connection.On) it else Connection.Starting(last) }
        JuistVpnService.start(context)
    }

    fun disconnect(context: Context) {
        want(context, false)
        // Off at once, so that the switch says so while the core stops.
        poller?.cancel()
        synchronized(publishing) {
            core = null
            _connection.value = Connection.Off(last)
        }
        JuistVpnService.stop(context)
    }

    // --- for JuistVpnService ---------------------------------------------------

    internal fun attached(c: CoreCalls) {
        synchronized(publishing) { core = c }
        poller?.cancel()
        poller = scope.launch {
            while (isActive) {
                // Nothing shows the status while the screen is off, the notification included.
                pace.first { it.interactive }
                refresh()
                delay(if (visible) 2_000 else 15_000)
            }
        }
    }

    internal fun detached(context: Context, reason: OffReason = OffReason.None) {
        if (reason == OffReason.Revoked) want(context, false)
        poller?.cancel()
        synchronized(publishing) {
            core = null
            // Turned on again while it stopped: the next core is on its way.
            if (reason != OffReason.None || _connection.value !is Connection.Starting) {
                _connection.value = Connection.Off(last, reason)
            }
        }
    }

    internal fun failed(message: String) {
        synchronized(publishing) {
            core = null
            _connection.value = Connection.Failed(message, last)
        }
    }

    /** Asks the core for its status, off the caller's thread. */
    fun refreshSoon() {
        scope.launch { refresh() }
    }

    /** Asks the core for its status now; it blocks. */
    fun refresh() {
        val c = core ?: return
        val view = runCatching { parseView(c.status()) }.getOrNull() ?: return
        synchronized(publishing) {
            if (core !== c) return
            val was = (_connection.value as? Connection.On)?.view
            _connection.value = Connection.On(view)
            // Kept for when the VPN is off, which needs the members, not how they were reached.
            if (view.inNetwork && (was == null || was.members.map { it.name } != view.members.map { it.name } || was.self != view.self)) {
                runCatching { cacheFile.writeText(coreJson.encodeToString(NetworkView.serializer(), view)) }
            } else if (!view.inNetwork) {
                cacheFile.delete()
            }
        }
    }

    private suspend fun runningCore(): CoreCalls? =
        core ?: withTimeoutOrNull(20_000) {
            connection.first { it is Connection.On || it is Connection.Failed || it is Connection.Off && it.reason != OffReason.None }
            core
        }

    // --- calls into the core ------------------------------------------------------

    /** Starts the core where it is off, and joins by invite as name; false where a join runs already. */
    @Synchronized
    fun join(context: Context, invite: String, name: String): Boolean {
        if (_join.value is JoinState.Running) return false
        _join.value = JoinState.Running(JoinStep.Starting)
        if (core == null) connect(context)
        joinJob = scope.launch {
            val c = runningCore()
            ensureActive()
            if (c == null) {
                _join.value = JoinState.Failed((connection.value as? Connection.Failed)?.message)
                return@launch
            }
            val result = runCatching {
                c.join(invite.trim(), name) { kind, text, votes, quorum ->
                    if (isActive) _join.update { joinStep(it, kind, text, votes, quorum) }
                }
            }
            refresh()
            // Cancelled by the person, whose screen has moved on.
            if (!isActive) return@launch
            _join.value = result.fold(
                onSuccess = { JoinState.Joined },
                // Stopped from elsewhere, as by the notification's action.
                onFailure = { JoinState.Failed(if (core !== c) null else it.message.orEmpty(), byCode = !InviteCode.isLink(invite)) },
            )
        }
        return true
    }

    @Synchronized
    fun cancelJoin() {
        joinJob?.cancel()
        joinJob = null
        core?.cancelJoin()
        _join.value = JoinState.Idle
    }

    fun clearJoin() {
        if (_join.value !is JoinState.Running) _join.value = JoinState.Idle
    }

    /** One echo to the member, its round trip in milliseconds. */
    suspend fun ping(identity: String): Result<Double> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { c.ping(identity) / 1000.0 }
    }

    /**
     * Deletes the state directory, keys and all, where the core cannot start
     * over it any more, as when Keystore lost the key that seals them. The
     * network still lists this device until an admin removes it.
     */
    fun startOver(context: Context) {
        disconnect(context)
        home(context).deleteRecursively()
        cacheFile.delete()
        _connection.value = Connection.Off(null)
    }

    /** Sends the phone's internet through the exit node with identity, or directly where it is null. */
    suspend fun useExit(identity: String?): Result<Unit> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { if (identity == null) c.exitOff() else c.useExit(identity) }.also { refresh() }
    }

    /** Forgets a network that removed this device, so it can join again. */
    suspend fun forget(): Result<Unit> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { c.forget() }.also { refresh() }
    }
}

/** The join's next state on an event of kind (internal/guest.EventKind). */
internal fun joinStep(was: JoinState, kind: Int, text: String, votes: Int, quorum: Int): JoinState {
    val run = was as? JoinState.Running ?: JoinState.Running(JoinStep.Starting)
    return when (kind) {
        1 -> run.copy(step = JoinStep.Looking)
        2 -> run.copy(step = JoinStep.Connected, relayed = text == "relay")
        // Without a quorum it only says the admin is still deciding.
        3 -> if (quorum == 0) run else run.copy(step = JoinStep.Waiting, votes = votes, quorum = quorum)
        4 -> run.copy(step = JoinStep.Meeting)
        5 -> run.copy(step = JoinStep.Compare, words = text.split('-', ' ').filter { it.isNotEmpty() })
        else -> run
    }
}

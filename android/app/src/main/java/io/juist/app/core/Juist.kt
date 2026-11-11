package io.juist.app.core

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.edit
import io.juist.mobile.Core
import io.juist.mobile.InviteListener
import io.juist.mobile.JoinListener
import io.juist.mobile.Mobile
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
import kotlinx.serialization.builtins.ListSerializer

/** Whether the core runs, and what it last said of each network, by slot. */
sealed interface Connection {
    /** The VPN is off; [last] is what the core said before it stopped, if it ever ran. */
    data class Off(val last: List<NetworkView>, val reason: OffReason = OffReason.None) : Connection {
        constructor(last: NetworkView?, reason: OffReason = OffReason.None) : this(listOfNotNull(last), reason)
    }

    data class Starting(val last: List<NetworkView>) : Connection {
        constructor(last: NetworkView?) : this(listOfNotNull(last))
    }

    data class On(val views: List<NetworkView>) : Connection {
        constructor(view: NetworkView) : this(listOf(view))

        /** The network the phone is in, where it is in one alone, or the first. */
        val view: NetworkView get() = views.firstOrNull { it.inNetwork } ?: views.first()
    }

    /** The core did not start; [message] is its own reason, in English. */
    data class Failed(val message: String, val last: List<NetworkView>) : Connection {
        constructor(message: String, last: NetworkView?) : this(message, listOfNotNull(last))
    }
}

enum class OffReason { None, Revoked }

/** How a join goes, as the core reports it (internal/guest's events). */
sealed interface JoinState {
    data object Idle : JoinState

    data class Running(val step: JoinStep, val relayed: Boolean = false, val words: List<String> = emptyList(),
        val votes: Int = 0, val quorum: Int = 0) : JoinState

    /** Joined, in the core's [slot]. */
    data class Joined(val slot: Int = 0) : JoinState

    /**
     * The join failed, by a code where [byCode], which only finds its host on
     * the LAN; [message] is the core's reason, null where juist stopped.
     */
    data class Failed(val message: String?, val byCode: Boolean = false) : JoinState
}

enum class JoinStep { Starting, Looking, Meeting, Connected, Compare, Waiting }

/** A call into the core while none runs. */
class CoreOff : IllegalStateException("juist is off")

/** What the core last said of every network, whether it runs or not. */
val Connection.views: List<NetworkView>
    get() = when (this) {
        is Connection.On -> views
        is Connection.Off -> last
        is Connection.Starting -> last
        is Connection.Failed -> last
    }

/** The networks the phone is in, by slot. */
val Connection.networks: List<NetworkView> get() = views.filter { it.inNetwork }

/** What the core last said of the network in slot. */
fun Connection.view(slot: Int): NetworkView? = views.firstOrNull { it.slot == slot }

/** What the core last said of the phone's network where it is in one alone, or of its first. */
val Connection.lastView: NetworkView?
    get() = networks.firstOrNull() ?: views.firstOrNull()

/** The state of the network that fares worst, as `juist status` orders them. */
val Connection.worstState: State?
    get() = networks.minByOrNull { it.state.ordinal }?.state

/** How many networks a phone is in at most, mobile.MaxNetworks. */
const val MAX_NETWORKS = 4

/** What [Juist] asks of a running core: the Go core's, or a test's. */
internal interface CoreCalls {
    /** Every network's view, a JSON list. */
    fun status(): String
    /** Joins by invite as name, telling progress each event (internal/guest.EventKind); the slot joined. */
    fun join(invite: String, name: String, progress: (kind: Int, text: String, votes: Int, quorum: Int) -> Unit): Int
    fun cancelJoin()
    /** One echo's round trip, in microseconds. */
    fun ping(slot: Int, identity: String): Long
    fun useExit(slot: Int, identity: String)
    fun exitOff(slot: Int)
    fun forget(slot: Int)
    fun leave(slot: Int)
    /** A JSON [Diagnosis]. */
    fun diagnose(): String
    /** The log's newest changes, JSON [Change]s. */
    fun changes(slot: Int): String
    fun setNames(slot: Int, on: Boolean)
    fun setPublicNames(slot: Int, on: Boolean)
    fun setHttpsOnly(slot: Int, on: Boolean)
    fun setPortMapping(slot: Int, on: Boolean)

    /** Founds network, this phone named name in it, seed's admin key its admin: its slot and break-glass line. */
    fun create(network: String, name: String, seed: ByteArray): Founded
    /** Offers an invite into slot's network until it ends; [admit] or [refuse] answer its comparison. */
    fun invite(slot: Int, minutes: Int, admin: String, events: InviteEvents)
    fun cancelInvite()
    fun admit(seed: ByteArray)
    fun refuse()
    /** Each reports whether the key's signature applied the change, else it waits for the other admins' votes. */
    /** lastVoucher agrees to take the network's last voucher, leaving freshness unchecked; else that is refused. */
    fun remove(slot: Int, identity: String, seed: ByteArray, lastVoucher: Boolean): Boolean
    fun grant(slot: Int, identity: String, role: String, on: Boolean, seed: ByteArray, lastVoucher: Boolean): Boolean
}

/** A network the phone founded: its slot, and its break-glass secret, shown once. */
data class Founded(val slot: Int, val breakGlass: String, val admin: String)

/** What an invite the phone offers says, from the core's thread. */
interface InviteEvents {
    fun ready(code: String, link: String)
    fun compare(words: String, name: String)
    fun event(kind: Int, name: String, text: String)
}

/** The Go core's calls. */
internal class GoCore(private val c: Core) : CoreCalls {
    override fun status(): String = c.status()
    override fun join(invite: String, name: String, progress: (Int, String, Int, Int) -> Unit): Int =
        c.join(invite, name, JoinListener { kind, text, votes, quorum -> progress(kind, text, votes, quorum) })
    override fun cancelJoin() = c.cancelJoin()
    override fun ping(slot: Int, identity: String): Long = c.ping(slot, identity)
    override fun useExit(slot: Int, identity: String) = c.useExit(slot, identity)
    override fun exitOff(slot: Int) = c.exitOff(slot)
    override fun forget(slot: Int) = c.forget(slot)
    override fun leave(slot: Int) = c.leave(slot)
    override fun diagnose(): String = c.diagnose()
    override fun changes(slot: Int): String = c.changes(slot)
    override fun setNames(slot: Int, on: Boolean) = c.setNames(slot, on)
    override fun setPublicNames(slot: Int, on: Boolean) = c.setPublicNames(slot, on)
    override fun setHttpsOnly(slot: Int, on: Boolean) = c.setHTTPSOnly(slot, on)
    override fun setPortMapping(slot: Int, on: Boolean) = c.setPortMapping(slot, on)
    override fun create(network: String, name: String, seed: ByteArray): Founded =
        c.create(network, name, seed).let { Founded(it.slot, it.breakGlass, Mobile.adminKeyOf(seed)) }
    override fun invite(slot: Int, minutes: Int, admin: String, events: InviteEvents) =
        c.invite(slot, minutes, admin, object : InviteListener {
            override fun ready(code: String, link: String) = events.ready(code, link)
            override fun compare(words: String, name: String) = events.compare(words, name)
            override fun event(kind: Int, name: String, text: String) = events.event(kind, name, text)
        })
    override fun cancelInvite() = c.cancelInvite()
    override fun admit(seed: ByteArray) = c.admit(seed)
    override fun refuse() = c.refuse()
    override fun remove(slot: Int, identity: String, seed: ByteArray, lastVoucher: Boolean): Boolean =
        c.remove(slot, identity, seed, lastVoucher)
    override fun grant(slot: Int, identity: String, role: String, on: Boolean, seed: ByteArray, lastVoucher: Boolean): Boolean =
        c.grant(slot, identity, role, on, seed, lastVoucher)
}

/** The process's one core, which [JuistVpnService] runs and the screens watch. */
object Juist {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var cacheFile: File

    private val _connection = MutableStateFlow<Connection>(Connection.Off(emptyList()))
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
        val last = runCatching { parseViews(cacheFile.readText()) }.getOrDefault(emptyList())
        _connection.value = Connection.Off(last)
    }

    /** The state directory of the phone's first network, kept from backups and transfers; the others' are beside it. */
    fun home(context: Context) = File(context.noBackupFilesDir, "juist")

    /** Every network's state directory, as mobile.Core.homeOf names them. */
    private fun homes(context: Context) = listOf(home(context)) + (1 until MAX_NETWORKS).map { File(context.noBackupFilesDir, "juist$it") }

    /** What the core last said of every network. */
    val last: List<NetworkView> get() = _connection.value.views

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
        val views = runCatching { parseViews(c.status()) }.getOrNull()?.takeIf { it.isNotEmpty() } ?: return
        synchronized(publishing) {
            if (core !== c) return
            val was = (_connection.value as? Connection.On)?.views
            _connection.value = Connection.On(views)
            // Kept for when the VPN is off, which needs the members, not how they were reached.
            val kept = views.filter { it.inNetwork }
            if (kept.isEmpty()) {
                cacheFile.delete()
            } else if (was == null || cached(was) != cached(kept)) {
                runCatching { cacheFile.writeText(coreJson.encodeToString(ListSerializer(NetworkView.serializer()), kept)) }
            }
        }
    }

    /** What of views the cache holds, so that it is written when that changes alone. */
    private fun cached(views: List<NetworkView>) =
        views.filter { it.inNetwork }.map { Triple(it.slot, it.self, it.members.map { m -> m.name } + it.network) }

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
                onSuccess = { JoinState.Joined(it) },
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

    /** One echo to the member of slot's network, its round trip in milliseconds. */
    suspend fun ping(slot: Int, identity: String): Result<Double> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { c.ping(slot, identity) / 1000.0 }
    }

    /**
     * Deletes every network's state directory, keys and all, where the core
     * cannot start over them any more, as when Keystore lost the key that
     * seals them. The networks still list this device until an admin removes it.
     */
    fun startOver(context: Context) {
        disconnect(context)
        homes(context).forEach { it.deleteRecursively() }
        cacheFile.delete()
        _connection.value = Connection.Off(emptyList())
    }

    /** Sends the phone's internet through the exit node with identity in slot's network, or directly where it is null. */
    suspend fun useExit(slot: Int, identity: String?): Result<Unit> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { if (identity == null) c.exitOff(slot) else c.useExit(slot, identity) }.also { refresh() }
    }

    /** Has the phone's lookups take slot's network's names, or leaves them out. */
    suspend fun setNames(slot: Int, on: Boolean): Result<Unit> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { c.setNames(slot, on) }.also { refresh() }
    }

    /** Has the phone resolve the public names slot's network points at members to them, or publicly. */
    suspend fun setPublicNames(slot: Int, on: Boolean): Result<Unit> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { c.setPublicNames(slot, on) }.also { refresh() }
    }

    /** Has slot's network reach its relays by TLS on 443 alone, or by every way. */
    suspend fun setHttpsOnly(slot: Int, on: Boolean): Result<Unit> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { c.setHttpsOnly(slot, on) }.also { refresh() }
    }

    /** Has slot's network ask the router to open a port for the phone, or not. */
    suspend fun setPortMapping(slot: Int, on: Boolean): Result<Unit> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { c.setPortMapping(slot, on) }.also { refresh() }
    }

    /**
     * Founds network with this phone named name in it, and seed's admin key
     * its one admin, starting the core where it is off.
     */
    suspend fun create(context: Context, network: String, name: String, seed: ByteArray): Result<Founded> {
        if (core == null) withContext(Dispatchers.Main) { connect(context) }
        return withContext(Dispatchers.IO) {
            val c = runningCore() ?: return@withContext Result.failure(CoreOff())
            runCatching { c.create(network, name, seed) }.also { refresh() }
        }
    }

    private val _invite = MutableStateFlow<InviteState>(InviteState.Idle)
    /** The invite the phone offers, if any, and the slot of the network it is into. */
    val invite: StateFlow<InviteState> = _invite.asStateFlow()
    @Volatile var inviteSlot: Int = -1
        private set
    @Volatile private var refused = false
    // Each invite's number: one that ended late says nothing of the next.
    private var inviteGen = 0

    /** Offers an invite into slot's network for minutes, naming the admin key admin; false where one is open. */
    @Synchronized
    fun invite(slot: Int, minutes: Int, admin: String): Boolean {
        if (_invite.value.open) return false
        val c = core ?: return false
        _invite.value = InviteState.Starting
        inviteSlot = slot
        refused = false
        val gen = ++inviteGen
        fun ours(change: (InviteState) -> InviteState) = synchronized(this) {
            if (gen == inviteGen) _invite.update(change)
        }
        scope.launch {
            val events = object : InviteEvents {
                override fun ready(code: String, link: String) = ours { InviteState.Offered(code, link) }

                override fun compare(words: String, name: String) = ours { InviteState.Comparing(words, name) }

                override fun event(kind: Int, name: String, text: String) {
                    when (kind) {
                        HOST_JOINED -> ours { InviteState.Joined(name) }
                        HOST_NO_LAN -> ours { if (it is InviteState.Offered) it.copy(noLan = true) else it }
                    }
                }
            }
            val result = runCatching { c.invite(slot, minutes, admin, events) }
            refresh()
            ours {
                when {
                    it is InviteState.Joined || it is InviteState.Idle -> it
                    refused -> InviteState.Ended(null, refused = true)
                    else -> InviteState.Ended(result.exceptionOrNull()?.message)
                }
            }
        }
        return true
    }

    /** Answers the comparison: seed's admin key admits the device, or, null, the words differ. */
    suspend fun answerInvite(seed: ByteArray?): Result<Unit> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        if (seed == null) {
            refused = true
            return@withContext runCatching { c.refuse() }
        }
        val was = _invite.value
        _invite.update { if (it is InviteState.Comparing) InviteState.Admitting(it.name) else it }
        runCatching { c.admit(seed) }.onFailure { _invite.compareAndSet(InviteState.Admitting((was as? InviteState.Comparing)?.name.orEmpty()), was) }
    }

    @Synchronized
    fun cancelInvite() {
        core?.cancelInvite()
        inviteGen++
        _invite.value = InviteState.Idle
    }

    private val _founded = MutableStateFlow<Founded?>(null)
    /** The network the phone just founded, its break-glass secret held in memory alone until its backup is done. */
    val founded: StateFlow<Founded?> = _founded.asStateFlow()
    internal fun founded(f: Founded?) {
        _founded.value = f
    }

    /** The sealed line a backup file is being written with, while the system's picker is open. */
    @Volatile var pendingBackup: String? = null


    /** Removes the member identity from slot's network, signed by seed's admin key: whether that applied it. */
    suspend fun remove(slot: Int, identity: String, seed: ByteArray, lastVoucher: Boolean = false): Result<Boolean> =
        withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { c.remove(slot, identity, seed, lastVoucher) }.also { refresh() }
    }

    /** Grants the member identity role, or takes it, signed by seed's admin key: whether that applied it. */
    suspend fun grant(slot: Int, identity: String, role: String, on: Boolean, seed: ByteArray, lastVoucher: Boolean = false):
        Result<Boolean> = withContext(Dispatchers.IO) {
            val c = core ?: return@withContext Result.failure(CoreOff())
            runCatching { c.grant(slot, identity, role, on, seed, lastVoucher) }.also { refresh() }
        }

    /** The newest changes of slot's log, newest first. */
    suspend fun changes(slot: Int): Result<List<Change>> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { coreJson.decodeFromString(ListSerializer(Change.serializer()), c.changes(slot)) }
    }

    /** What the core says of how the phone's traffic fares, null while it is off. */
    fun diagnosis(): Diagnosis? = core?.let { c -> runCatching { coreJson.decodeFromString(Diagnosis.serializer(), c.diagnose()) }.getOrNull() }

    /** Forgets slot's network, one that removed this device, so it can join again. */
    suspend fun forget(slot: Int): Result<Unit> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { c.forget(slot) }.also { refresh() }
    }

    /** Leaves slot's network, which lists this phone until an admin removes it; the others stay as they are. */
    suspend fun leave(slot: Int): Result<Unit> = withContext(Dispatchers.IO) {
        val c = core ?: return@withContext Result.failure(CoreOff())
        runCatching { c.leave(slot) }.also { refresh() }
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

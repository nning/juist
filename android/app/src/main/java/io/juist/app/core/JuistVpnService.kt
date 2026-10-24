package io.juist.app.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.PowerManager
import android.util.Log
import io.juist.app.BuildConfig
import io.juist.app.MainActivity
import io.juist.app.R
import io.juist.app.ui.stateLabel
import androidx.core.content.ContextCompat
import io.juist.mobile.Core
import io.juist.mobile.Mobile
import io.juist.mobile.Platform
import java.net.InetAddress
import java.util.concurrent.Executors
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable

/**
 * Runs the core while the VPN is on: in the foreground, so that the mesh stays
 * up in Doze, at the pace the phone allows, and holding a multicast lock while
 * not saving battery, so that mDNS finds members on the Wi-Fi. Its device
 * carries the network's addresses and the phone's DNS, and the phone's
 * internet only while an exit node is used.
 */
class JuistVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    // Confined to the serial thread, as are the fields below.
    @Volatile private var core: Core? = null
    @Volatile private var destroyed = false
    private var multicast: WifiManager.MulticastLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var networkThread: HandlerThread? = null
    private var notifier: Job? = null
    private var multicastHolder: Job? = null
    private var paceReceiver: BroadcastReceiver? = null
    private var pacer: Job? = null
    private val metered = MutableStateFlow(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            Juist.want(this, false)
            serial.execute { shutDown(OffReason.None, startId) }
            return START_NOT_STICKY
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification(NotificationLines.of(this, null)), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification(NotificationLines.of(this, null)))
        }
        serial.execute { startCore() }
        return START_STICKY
    }

    private fun startCore() {
        if (core != null || destroyed) return
        try {
            val home = Juist.home(this).apply { mkdirs() }
            val c = Mobile.start(home.path, platform)
            core = c
            followPace(c)
            holdMulticast()
            followNetworks()
            Juist.attached(GoCore(c))
            notifier = scope.launch {
                Juist.connection.mapNotNull { (it as? Connection.On)?.view }
                    .map { NotificationLines.of(this@JuistVpnService, it) }
                    .distinctUntilChanged()
                    .collect { getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(it)) }
            }
        } catch (e: Exception) {
            Log.w(TAG, "starting the core", e)
            Juist.failed(e.message.orEmpty())
            stopSelf()
        }
    }

    override fun onRevoke() = serial.execute { shutDown(OffReason.Revoked) }

    override fun onDestroy() {
        destroyed = true
        serial.execute {
            if (stopCore()) Juist.detached(this)
            getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
            scope.cancel()
        }
        super.onDestroy()
    }

    /**
     * Stops the core and the service, unless a start came after startId's
     * stop, whose core then starts after this one stopped.
     */
    private fun shutDown(reason: OffReason, startId: Int? = null) {
        stopCore()
        Juist.detached(this, reason)
        if (startId == null || stopSelfResult(startId)) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    /** Stops the core, reporting whether one ran. */
    private fun stopCore(): Boolean {
        val c = core ?: return false
        notifier?.cancel()
        notifier = null
        paceReceiver?.let { unregisterReceiver(it) }
        paceReceiver = null
        pacer?.cancel()
        pacer = null
        multicastHolder?.cancel()
        multicastHolder = null
        networkCallback?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
        networkCallback = null
        networkThread?.quitSafely()
        networkThread = null
        metered.value = false
        core = null
        c.close()
        multicast?.let { lock ->
            multicast = null
            synchronized(lock) { if (lock.isHeld) lock.release() }
        }
        return true
    }

    private fun holdMulticast() {
        val lock = getSystemService(WifiManager::class.java)?.createMulticastLock("juist-mdns")?.apply {
            setReferenceCounted(false)
        } ?: return
        multicast = lock
        multicastHolder = scope.launch {
            combine(Juist.pace, Juist.join, ::holdsMulticast).distinctUntilChanged().collect { hold ->
                synchronized(lock) { if (hold && multicast === lock) lock.acquire() else if (lock.isHeld) lock.release() }
            }
        }
    }

    /**
     * Tells the core to save battery while the screen is off, the phone dozes
     * or battery saver is on, and on a metered network while the app is not in
     * front.
     */
    private fun followPace(c: Core) {
        val pm = getSystemService(PowerManager::class.java)
        fun read() = Pace(pm.isInteractive, pm.isDeviceIdleMode, pm.isPowerSaveMode)
        val power = MutableStateFlow(read())
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                power.value = read()
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
            addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
        }
        ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        paceReceiver = receiver
        pacer = scope.launch {
            combine(power, metered, Juist.shown) { p, m, shown -> p.copy(metered = m, inFront = shown) }
                .distinctUntilChanged()
                .collect { p ->
                    if (core === c) {
                        c.setSaving(p.saving)
                        Juist.paced(p)
                    }
                }
        }
    }

    /**
     * Tells Android which network the tunnels go out on, so that it counts the
     * VPN as that network, and the core that it changed, which on Android it
     * does not notice for minutes by itself.
     */
    private fun followNetworks() {
        val thread = HandlerThread("juist-underlay").apply { start() }
        val follower = UnderlayFollower(
            use = { setUnderlyingNetworks(it?.let { n -> arrayOf(n) }) },
            changed = { iface, resolvers -> core?.networkChanged(iface, resolvers) },
            metered = { metered.value = it },
        )
        getSystemService(ConnectivityManager::class.java)
            .registerBestMatchingNetworkCallback(underlayRequest(), follower, Handler(thread.looper))
        networkCallback = follower
        networkThread = thread
    }

    private val platform = object : Platform {
        override fun protect(fd: Int): Boolean = this@JuistVpnService.protect(fd)

        override fun establish(config: String): Int {
            val b = Builder()
                .setSession(Juist.last?.network?.takeIf { it.isNotEmpty() } ?: getString(R.string.app_name))
                .setConfigureIntent(openApp())
            // No allowBypass: no app leaves the tunnel by binding to the network beside it.
            configureVpn(config, object : VpnTarget {
                override fun addAddress(address: InetAddress, prefixLength: Int) { b.addAddress(address, prefixLength) }
                override fun addRoute(address: InetAddress, prefixLength: Int) { b.addRoute(address, prefixLength) }
                override fun addDnsServer(address: InetAddress) { b.addDnsServer(address) }
                override fun addSearchDomain(domain: String) { b.addSearchDomain(domain) }
                override fun setMtu(mtu: Int) { b.setMtu(mtu) }
            })
            val pfd = b.establish() ?: throw IllegalStateException(getString(R.string.vpn_not_established))
            return pfd.detachFd()
        }

        override fun interfaces(): String = interfacesJson()

        override fun seal(plain: ByteArray): ByteArray = KeystoreSealer.seal(plain)

        override fun open(sealed: ByteArray): ByteArray = KeystoreSealer.open(sealed)

        override fun log(line: String) {
            Diagnostics.add(line)
            if (BuildConfig.DEBUG) Log.d(TAG, line)
        }
    }

    private fun openApp(): PendingIntent = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE,
    )

    private fun notification(lines: NotificationLines): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW)
                    .apply { setShowBadge(false) },
            )
        }
        val stop = PendingIntent.getService(
            this, 1, Intent(this, JuistVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(lines.title)
            .setContentText(lines.text)
            .setContentIntent(openApp())
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(Notification.Action.Builder(null, getString(R.string.action_disconnect), stop).build())
            .build()
    }

    companion object {
        private const val TAG = "juist"
        private const val CHANNEL = "status"
        private const val NOTIFICATION_ID = 1
        private const val ACTION_STOP = "io.juist.STOP"

        /** Where cores start and stop, one after the other and off the main thread. */
        private val serial = Executors.newSingleThreadExecutor { Thread(it, "juist-core") }

        fun start(context: Context) {
            context.startForegroundService(Intent(context, JuistVpnService::class.java))
        }

        fun stop(context: Context) {
            context.startService(Intent(context, JuistVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}

/**
 * What the tunnels go out on: the best network outside any VPN. The app's
 * default network is its own VPN once that is up, and follows it instead.
 */
internal fun underlayRequest(): NetworkRequest = NetworkRequest.Builder()
    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    .build()

/**
 * Hands the network [underlayRequest] matches to use, null where there is
 * none, its interface's name and how it resolves, an [UnderlayDns] as JSON,
 * to changed, "" for none, and whether it is metered to metered. A network
 * lost after another replaced it changes nothing.
 */
internal class UnderlayFollower(
    private val use: (Network?) -> Unit,
    private val changed: (iface: String, resolvers: String) -> Unit,
    private val metered: (Boolean) -> Unit = {},
) : ConnectivityManager.NetworkCallback() {
    private var current: Network? = null

    override fun onAvailable(network: Network) {
        current = network
        use(network)
    }

    // Android calls both after every onAvailable.
    override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
        if (network == current) metered(isMetered(capabilities))
    }

    override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
        if (network == current) changed(properties.interfaceName.orEmpty(), UnderlayDns.of(properties).json())
    }

    override fun onLost(network: Network) {
        if (network != current) return
        current = null
        use(null)
        changed("", "")
        metered(false)
    }
}

/**
 * How a network resolves, as the core reads it (mobile/platform.go's
 * underlayDNS): its resolvers, whether automatic Private DNS found them
 * answering DNS over TLS, and the host Private DNS sends every lookup to, set
 * only in its strict mode.
 */
@Serializable
internal data class UnderlayDns(
    val servers: List<String> = emptyList(),
    val overTls: Boolean = false,
    val privateDns: String = "",
) {
    fun json(): String = coreJson.encodeToString(serializer(), this)

    companion object {
        fun of(p: LinkProperties) = UnderlayDns(
            servers = p.dnsServers.mapNotNull { it.hostAddress },
            overTls = p.isPrivateDnsActive && p.privateDnsServerName == null,
            privateDns = p.privateDnsServerName.orEmpty(),
        )
    }
}

/** Whether traffic on a network with capabilities costs, as mobile data does. */
internal fun isMetered(capabilities: NetworkCapabilities) =
    !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) &&
        !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_TEMPORARILY_NOT_METERED)

/** What the notification says of view: the network, and its state. */
internal data class NotificationLines(val title: String, val text: String) {
    companion object {
        fun of(context: Context, view: NetworkView?): NotificationLines {
            val title = view?.network?.takeIf { it.isNotEmpty() } ?: context.getString(R.string.app_name)
            if (view == null) return NotificationLines(title, context.getString(R.string.state_starting))
            return NotificationLines(title, context.getString(stateLabel(view.state)))
        }
    }
}

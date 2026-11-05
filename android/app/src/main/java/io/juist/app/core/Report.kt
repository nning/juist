package io.juist.app.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.PowerManager
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * What a person copies when something goes wrong: the app's version, how
 * Android sees the phone's networks and the VPN, what the core says of the
 * phone's traffic, and the core's log.
 */
object Report {
    fun text(context: Context, version: String): String = buildString {
        appendLine("juist $version, Android ${android.os.Build.VERSION.RELEASE} (API ${android.os.Build.VERSION.SDK_INT})")
        appendLine()
        appendLine("networks:")
        append(networks(context))
        appendLine(power(context))
        Juist.diagnosis()?.let { appendLine(); append(diagnosis(it)) }
        appendLine()
        appendLine("log:")
        append(Diagnostics.text())
    }

    private val time = SimpleDateFormat("HH:mm:ss", Locale.ROOT)

    private fun at(unix: Long) = if (unix == 0L) "never" else time.format(Date(unix * 1000))

    /** Each network Android has, the default one marked, with what decides whether apps may use it. */
    @Suppress("DEPRECATION")
    fun networks(context: Context): String = buildString {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return@buildString
        val active = cm.activeNetwork
        for (n in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(n) ?: continue
            val lp = cm.getLinkProperties(n)
            append(if (n == active) "* " else "  ")
            append(transports(caps)).append(' ').append(lp?.interfaceName ?: "?")
            append(' ').append(flags(caps).joinToString(","))
            if (lp != null) {
                if (lp.isPrivateDnsActive) append(" privatedns=").append(lp.privateDnsServerName ?: "auto")
                append(" dns=").append(lp.dnsServers.mapNotNull { it.hostAddress }.joinToString(","))
                append(" routes=").append(lp.routes.size)
            }
            appendLine()
        }
        appendLine("background data: ${background(cm.restrictBackgroundStatus)}")
    }

    private fun transports(c: NetworkCapabilities) = listOf(
        NetworkCapabilities.TRANSPORT_VPN to "vpn", NetworkCapabilities.TRANSPORT_WIFI to "wifi",
        NetworkCapabilities.TRANSPORT_CELLULAR to "cellular", NetworkCapabilities.TRANSPORT_ETHERNET to "ethernet",
    ).filter { c.hasTransport(it.first) }.joinToString("+") { it.second }.ifEmpty { "other" }

    private fun flags(c: NetworkCapabilities) = listOf(
        NetworkCapabilities.NET_CAPABILITY_INTERNET to "internet", NetworkCapabilities.NET_CAPABILITY_VALIDATED to "validated",
        NetworkCapabilities.NET_CAPABILITY_NOT_METERED to "unmetered", NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED to "notsuspended",
        NetworkCapabilities.NET_CAPABILITY_FOREGROUND to "foreground", NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL to "captive",
        NetworkCapabilities.NET_CAPABILITY_NOT_VPN to "notvpn",
    ).filter { c.hasCapability(it.first) }.map { it.second }

    private fun background(status: Int) = when (status) {
        ConnectivityManager.RESTRICT_BACKGROUND_STATUS_DISABLED -> "allowed"
        ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED -> "data saver on, juist exempt"
        ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED -> "data saver on"
        else -> "unknown"
    }

    private fun power(context: Context): String {
        val pm = context.getSystemService(PowerManager::class.java) ?: return ""
        return "power: interactive=${pm.isInteractive} idle=${pm.isDeviceIdleMode} saver=${pm.isPowerSaveMode} " +
            "unrestricted=${pm.isIgnoringBatteryOptimizations(context.packageName)}"
    }

    fun diagnosis(d: Diagnosis): String = buildString {
        appendLine("vpn: established ${d.established} times, last ${at(d.lastEstablished)}; saving=${d.saving}")
        val dns = d.dns
        appendLine("lookups: ${dns.queries} asked, ${dns.failed} failed, ${dns.slow} slow, slowest ${dns.maxMillis} ms")
        for (l in dns.recent) {
            appendLine("  ${at(l.at)} ${l.name} ${l.type} ${l.millis} ms ${l.why.ifEmpty { "slow" }}")
        }
    }
}

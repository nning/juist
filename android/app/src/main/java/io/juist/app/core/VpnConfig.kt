package io.juist.app.core

import java.net.InetAddress
import kotlinx.serialization.Serializable

/** The calls of `VpnService.Builder` a VPN is brought up with. */
internal interface VpnTarget {
    fun addAddress(address: InetAddress, prefixLength: Int)
    fun addRoute(address: InetAddress, prefixLength: Int)
    fun addDnsServer(address: InetAddress)
    fun setMtu(mtu: Int)
}

/** What the core hands `Platform.establish`: mobile/testdata/establish.json is one. */
@Serializable
internal data class EstablishConfig(
    val addrs: List<String>,
    val routes: List<String>,
    val dns: List<String> = emptyList(),
    val mtu: Int,
)

/**
 * Brings t up as config, the core's, says: its addresses, its routes, and
 * its DNS servers, set only while an exit node is used, which then answers
 * all of the phone's lookups.
 */
internal fun configureVpn(config: String, t: VpnTarget) {
    val c = coreJson.decodeFromString(EstablishConfig.serializer(), config)
    t.setMtu(c.mtu)
    for (a in c.addrs) prefix(a).let { (addr, bits) -> t.addAddress(addr, bits) }
    for (r in c.routes) prefix(r).let { (addr, bits) -> t.addRoute(addr, bits) }
    for (d in c.dns) t.addDnsServer(InetAddress.getByName(d))
}

private fun prefix(s: String): Pair<InetAddress, Int> {
    val (addr, bits) = s.split('/', limit = 2)
    return InetAddress.getByName(addr) to bits.toInt()
}

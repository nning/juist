package io.juist.app.core

import java.net.Inet6Address
import java.net.NetworkInterface
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer

/** One network interface as mobile/platform.go's iface reads it. */
@Serializable
internal data class Iface(
    val name: String,
    val index: Int,
    val mtu: Int,
    val up: Boolean,
    val loopback: Boolean,
    val multicast: Boolean,
    val addrs: List<String>,
)

/**
 * The phone's network interfaces as JSON, which Go cannot read from the kernel
 * in an app. VPN devices are left out, juist's own among them: an address
 * there reaches nobody outside this phone.
 */
internal fun interfacesJson(): String {
    val list = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        .filterNot { it.name.startsWith("tun") || it.isVirtual }
        .map { ifc ->
            Iface(
                name = ifc.name,
                index = ifc.index,
                mtu = runCatching { ifc.mtu }.getOrDefault(0),
                up = runCatching { ifc.isUp }.getOrDefault(false),
                loopback = runCatching { ifc.isLoopback }.getOrDefault(false),
                multicast = runCatching { ifc.supportsMulticast() }.getOrDefault(false),
                addrs = ifc.interfaceAddresses.mapNotNull { a ->
                    val ip = a.address ?: return@mapNotNull null
                    val host = if (ip is Inet6Address) ip.hostAddress?.substringBefore('%') else ip.hostAddress
                    host?.let { "$it/${a.networkPrefixLength}" }
                },
            )
        }
    return coreJson.encodeToString(ListSerializer(Iface.serializer()), list)
}

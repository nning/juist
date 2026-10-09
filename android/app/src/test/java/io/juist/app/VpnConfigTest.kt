package io.juist.app

import io.juist.app.core.VpnTarget
import io.juist.app.core.configureVpn
import java.io.File
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Test

class VpnConfigTest {
    /** What the builder was told, as prefixes. */
    private class Recorder : VpnTarget {
        val addrs = mutableListOf<String>()
        val routes = mutableListOf<String>()
        val dns = mutableListOf<String>()
        var mtuSet = 0

        override fun addAddress(address: InetAddress, prefixLength: Int) { addrs += "${address.hostAddress}/$prefixLength" }
        override fun addRoute(address: InetAddress, prefixLength: Int) { routes += "${address.hostAddress}/$prefixLength" }
        override fun addDnsServer(address: InetAddress) { dns += address.hostAddress!! }
        override fun setMtu(mtu: Int) { mtuSet = mtu }
    }

    /**
     * mobile/testdata/establish.json, which the Go side's test holds the core
     * to: through an exit node, its routes and DNS servers reach the builder,
     * which a field the app no longer read would leave out unnoticed.
     */
    @Test
    fun bringsTheVpnUpAsTheCoreSays() {
        val r = Recorder()
        configureVpn(File("../../mobile/testdata/establish.json").readText(), r)
        assertEquals(listOf("100.64.0.7/32", "fd00:1:2:0:0:0:0:7/128"), r.addrs)
        assertEquals(listOf("100.64.0.0/10", "fd00:1:2:0:0:0:0:0/48", "0.0.0.0/1", "128.0.0.0/2", "2000:0:0:0:0:0:0:0/3"), r.routes)
        assertEquals(listOf("100.64.0.1", "fd00:1:2:0:0:0:0:1"), r.dns)
        assertEquals(1280, r.mtuSet)
    }

    /** Without an exit node, the core names no DNS server, and the phone keeps its own. */
    @Test
    fun setsNoDnsServerWithoutOne() {
        val r = Recorder()
        configureVpn("""{"addrs":["100.64.0.7/32"],"routes":["100.64.0.0/10"],"mtu":1280}""", r)
        assertEquals(emptyList<String>(), r.dns)
        assertEquals(listOf("100.64.0.0/10"), r.routes)
    }
}

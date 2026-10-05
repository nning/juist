package io.juist.app

import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import io.juist.app.core.UnderlayFollower
import io.juist.app.core.underlayRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowNetwork

@RunWith(RobolectricTestRunner::class)
class UnderlayTest {
    private val used = mutableListOf<Network?>()
    private val changed = mutableListOf<String>()
    private val follower = UnderlayFollower(use = { used += it }, changed = { changed += it })

    private fun link(name: String) = LinkProperties().apply { interfaceName = name }

    @Test
    fun followsNoVpn() {
        val r = underlayRequest()
        assertTrue(r.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
        assertTrue(r.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
    }

    @Test
    fun aReplacedNetworkLostLaterChangesNothing() {
        val wifi = ShadowNetwork.newInstance(100)
        val cell = ShadowNetwork.newInstance(101)
        follower.onAvailable(wifi)
        follower.onLinkPropertiesChanged(wifi, link("wlan0"))
        follower.onAvailable(cell)
        follower.onLinkPropertiesChanged(cell, link("rmnet0"))
        follower.onLost(wifi)
        follower.onLinkPropertiesChanged(wifi, link("wlan0"))
        assertEquals(listOf(wifi, cell), used)
        assertEquals(listOf("wlan0", "rmnet0"), changed)
    }

    @Test
    fun theLastNetworkLostLeavesNone() {
        val wifi = ShadowNetwork.newInstance(100)
        follower.onAvailable(wifi)
        follower.onLinkPropertiesChanged(wifi, link("wlan0"))
        follower.onLost(wifi)
        assertEquals(listOf(wifi, null), used)
        assertEquals(listOf("wlan0", ""), changed)
    }
}

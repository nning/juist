package io.juist.app

import android.app.Application
import android.content.Intent
import io.juist.app.core.Connection
import io.juist.app.core.CoreCalls
import io.juist.app.core.JoinState
import io.juist.app.core.Juist
import io.juist.app.core.JuistVpnService
import io.juist.app.core.OffReason
import io.juist.app.core.StartReceiver
import io.juist.app.core.State
import io.juist.app.core.networks
import io.juist.app.core.view
import io.juist.app.core.worstState
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.shadows.ShadowVpnService

/** A core that answers with view.json, and joins as it is told. */
private class FakeCore : CoreCalls {
    var status = File("../../mobile/testdata/view.json").readText()
    var joinEvents = listOf<Pair<Int, String>>()
    var joinError: Exception? = null
    var joinSlot = 0
    var exit: String? = "unset"
    var exitSlot = -1
    var left = -1

    override fun status() = status
    override fun join(invite: String, name: String, progress: (Int, String, Int, Int) -> Unit): Int {
        for ((kind, text) in joinEvents) progress(kind, text, 0, 0)
        joinError?.let { throw it }
        return joinSlot
    }
    override fun cancelJoin() {}
    override fun ping(slot: Int, identity: String) = 1500L
    override fun useExit(slot: Int, identity: String) { exit = identity; exitSlot = slot }
    override fun exitOff(slot: Int) { exit = null; exitSlot = slot }
    override fun forget(slot: Int) {}
    override fun leave(slot: Int) { left = slot }
    var names: Boolean? = null
    override fun diagnose() = """{"established":2,"dns":{"queries":3,"failed":1}}"""
    override fun changes(slot: Int) = """[{"index":4,"what":"admit phone"}]"""
    override fun setNames(slot: Int, on: Boolean) { names = on }
    override fun setHttpsOnly(slot: Int, on: Boolean) {}
}

/** Two networks as the core lists them, view.json's in slot 0 and an office in slot 2, and a slot in none. */
internal fun twoNetworks(): String {
    val home = File("../../mobile/testdata/view.json").readText().trim()
    return """[${home.dropLast(1)},"slot":0},{"slot":1,"state":"none"},{"slot":2,"state":"waiting","network":"office","self":{"name":"phone"}}]"""
}

@RunWith(RobolectricTestRunner::class)
class JuistTest {
    private val app: Application = RuntimeEnvironment.getApplication()
    private val core = FakeCore()

    @Before
    fun fresh() {
        File(app.noBackupFilesDir, "last-status.json").delete()
        Juist.init(app)
    }

    @After
    fun off() {
        Juist.cancelJoin()
        Juist.disconnect(app)
    }

    private fun startedService(): Intent? = shadowOf(app).nextStartedService

    /** Starting until the core runs, on with its status, off once stopped; the wish kept for a reboot. */
    @Test
    fun followsTheCore() {
        Juist.connect(app)
        assertTrue(Juist.connection.value is Connection.Starting)
        assertTrue(Juist.wanted(app))
        assertEquals(JuistVpnService::class.java.name, startedService()?.component?.className)

        Juist.attached(core)
        Juist.refresh()
        val on = Juist.connection.value as Connection.On
        assertEquals(State.Connected, on.view.state)

        Juist.disconnect(app)
        assertEquals(Connection.Off(on.view), Juist.connection.value)
        assertFalse(Juist.wanted(app))
    }

    /** Another VPN taking over is said, and the VPN is not wanted on again after a reboot. */
    @Test
    fun aRevokedVpnIsOffAndNotWanted() {
        Juist.connect(app)
        Juist.attached(core)
        Juist.refresh()
        Juist.detached(app, OffReason.Revoked)
        assertEquals(OffReason.Revoked, (Juist.connection.value as Connection.Off).reason)
        assertFalse(Juist.wanted(app))
    }

    /** Turned on again while the last core stops, it stays starting. */
    @Test
    fun onAgainWhileStoppingStaysStarting() {
        Juist.connect(app)
        Juist.detached(app)
        assertTrue(Juist.connection.value is Connection.Starting)
    }

    /** A core that fails says why, and the last view stays. */
    @Test
    fun aFailedCoreSaysWhy() {
        Juist.connect(app)
        Juist.attached(core)
        Juist.refresh()
        Juist.failed("keystore lost its key")
        val failed = Juist.connection.value as Connection.Failed
        assertEquals("keystore lost its key", failed.message)
        assertEquals(State.Connected, failed.last.first().state)
    }

    /** Off, after the process started anew, the network's last view is shown. */
    @Test
    fun theLastViewOutlivesTheProcess() {
        Juist.connect(app)
        Juist.attached(core)
        Juist.refresh()
        Juist.disconnect(app)
        Juist.init(app)
        assertEquals(State.Connected, (Juist.connection.value as Connection.Off).last.first().state)
    }

    /** A status the core cannot give changes nothing; one of a core gone is not published. */
    @Test
    fun noStatusOfACoreGone() {
        Juist.connect(app)
        core.status = "not json"
        Juist.attached(core)
        Juist.refresh()
        assertTrue(Juist.connection.value is Connection.Starting)
        Juist.disconnect(app)
        core.status = File("../../mobile/testdata/view.json").readText()
        Juist.refresh()
        assertTrue(Juist.connection.value is Connection.Off)
    }

    /** A join follows the core's events to its end, and says why it failed, by code or by link. */
    @Test
    fun aJoinEndsAsTheCoreSays() = runBlocking {
        Juist.attached(core)
        core.joinEvents = listOf(1 to "", 2 to "relay")
        assertTrue(Juist.join(app, "juist:abc@192.0.2.1:41642", "pixel"))
        assertEquals(JoinState.Joined(0), withTimeout(5_000) { Juist.join.first { it !is JoinState.Running } })

        Juist.clearJoin()
        core.joinError = IllegalStateException("the code was not found")
        assertTrue(Juist.join(app, "42-drumbeat-tolerance-glucose", "pixel"))
        val failed = withTimeout(5_000) { Juist.join.first { it is JoinState.Failed } } as JoinState.Failed
        assertEquals("the code was not found", failed.message)
        assertTrue(failed.byCode)
    }

    /** An exit node chosen, or none, reaches the core. */
    @Test
    fun anExitNodeIsChosen() = runBlocking {
        Juist.attached(core)
        assertTrue(Juist.useExit(2, "node-a").isSuccess)
        assertEquals("node-a", core.exit)
        assertEquals(2, core.exitSlot)
        assertTrue(Juist.useExit(2, null).isSuccess)
        assertNull(core.exit)
        Juist.disconnect(app)
        assertTrue(Juist.useExit(2, "node-a").isFailure)
    }

    /** The names setting reaches the core, the log's changes and the diagnosis come from it, and none while it is off. */
    @Test
    fun settingsChangesAndTheDiagnosisGoThroughTheCore() = runBlocking {
        Juist.attached(core)
        assertTrue(Juist.setNames(0, false).isSuccess)
        assertEquals(false, core.names)
        assertEquals("admit phone", Juist.changes(0).getOrThrow().single().what)
        assertEquals(1, Juist.diagnosis()?.dns?.failed)
        Juist.disconnect(app)
        assertTrue(Juist.setNames(0, true).isFailure)
        assertNull(Juist.diagnosis())
    }

    /** Each network the core lists is one the phone is in, by slot, kept across the process, and one is left alone. */
    @Test
    fun severalNetworksAreFollowedAndOneLeft() = runBlocking {
        core.status = twoNetworks()
        Juist.connect(app)
        Juist.attached(core)
        Juist.refresh()
        val on = Juist.connection.value as Connection.On
        assertEquals(listOf(0, 2), on.networks.map { it.slot })
        assertEquals("office", on.view(2)?.network)
        assertEquals(State.Waiting, on.worstState)
        core.joinSlot = 2
        assertTrue(Juist.join(app, "juist:abc@192.0.2.1:41642", "pixel"))
        assertEquals(JoinState.Joined(2), withTimeout(5_000) { Juist.join.first { it !is JoinState.Running } })
        assertTrue(Juist.leave(2).isSuccess)
        assertEquals(2, core.left)

        Juist.disconnect(app)
        Juist.init(app)
        assertEquals(listOf("home", "office"), Juist.connection.value.networks.map { it.network })
    }

    /** A status kept by an app that knew one network is that network's, in slot 0. */
    @Test
    fun aStatusKeptForOneNetworkIsRead() {
        File(app.noBackupFilesDir, "last-status.json").writeText(File("../../mobile/testdata/view.json").readText())
        Juist.init(app)
        val last = (Juist.connection.value as Connection.Off).last
        assertEquals(listOf(0), last.map { it.slot })
        assertEquals(State.Connected, last.single().state)
    }

    /** After a reboot or an update, the VPN is on again where it was wanted. */
    @Test
    fun aRebootTurnsOnWhatWasOn() {
        ShadowVpnService.setPrepareResult(null) // consent given before
        val boot = Intent(Intent.ACTION_BOOT_COMPLETED)
        Juist.connect(app)
        startedService()
        StartReceiver().onReceive(app, boot)
        assertEquals(JuistVpnService::class.java.name, startedService()?.component?.className)

        Juist.disconnect(app)
        startedService() // the service told to stop
        StartReceiver().onReceive(app, boot)
        StartReceiver().onReceive(app, Intent(Intent.ACTION_MY_PACKAGE_REPLACED))
        assertNull(startedService())

        Juist.connect(app)
        startedService()
        StartReceiver().onReceive(app, Intent(Intent.ACTION_SCREEN_ON))
        assertNull(startedService())

        // Consent withdrawn meanwhile: Android would refuse the VPN.
        ShadowVpnService.setPrepareResult(Intent("android.net.vpn.SETUP_VPN"))
        StartReceiver().onReceive(app, boot)
        assertNull(startedService())
    }
}

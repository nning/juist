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
    var exit: String? = "unset"

    override fun status() = status
    override fun join(invite: String, name: String, progress: (Int, String, Int, Int) -> Unit) {
        for ((kind, text) in joinEvents) progress(kind, text, 0, 0)
        joinError?.let { throw it }
    }
    override fun cancelJoin() {}
    override fun ping(identity: String) = 1500L
    override fun useExit(identity: String) { exit = identity }
    override fun exitOff() { exit = null }
    override fun forget() {}
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
        assertEquals(State.Connected, failed.last?.state)
    }

    /** Off, after the process started anew, the network's last view is shown. */
    @Test
    fun theLastViewOutlivesTheProcess() {
        Juist.connect(app)
        Juist.attached(core)
        Juist.refresh()
        Juist.disconnect(app)
        Juist.init(app)
        assertEquals(State.Connected, (Juist.connection.value as Connection.Off).last?.state)
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
        assertEquals(JoinState.Joined, withTimeout(5_000) { Juist.join.first { it !is JoinState.Running } })

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
        assertTrue(Juist.useExit("node-a").isSuccess)
        assertEquals("node-a", core.exit)
        assertTrue(Juist.useExit(null).isSuccess)
        assertNull(core.exit)
        Juist.disconnect(app)
        assertTrue(Juist.useExit("node-a").isFailure)
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

package io.juist.app

import android.content.Intent
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import io.juist.app.core.CoreCalls
import io.juist.app.core.JoinState
import io.juist.app.core.Juist
import io.juist.app.core.MAX_NETWORKS
import io.juist.app.ui.AppRoot
import io.juist.app.ui.LocalInviteChecks
import io.juist.app.ui.Route
import io.juist.app.ui.decode
import io.juist.app.ui.encode
import io.juist.app.ui.theme.JuistTheme
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class AppRootTest {
    @get:Rule
    val compose = createAndroidComposeRule<ComponentActivity>()

    private val link = "juist:abc@192.0.2.1:41642"

    @Before
    fun off() {
        Juist.init(compose.activity)
    }

    @After
    fun stop() {
        Juist.cancelJoin()
        Juist.disconnect(compose.activity)
    }

    private fun text(id: Int) = compose.activity.getString(id)

    private fun show(opened: MutableState<String?>) = compose.setContent {
        CompositionLocalProvider(LocalInviteChecks provides FakeInviteChecks) { JuistTheme { AppRoot(opened) } }
    }

    /** A link opened from elsewhere asks to join, and joins nothing until tapped; back is the welcome. */
    @Test
    fun aLinkOpenedAsksToJoin() {
        val opened = mutableStateOf<String?>(link)
        show(opened)
        compose.onNodeWithText(text(R.string.confirm_link_opened)).assertIsDisplayed()
        assertNull(opened.value)
        assertEquals(JoinState.Idle, Juist.join.value)
        compose.runOnUiThread { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithText(text(R.string.welcome_title)).assertIsDisplayed()
    }

    private var status = ""

    private fun attach(status: String) {
        this.status = status
        Juist.attached(object : CoreCalls {
            override fun status() = this@AppRootTest.status
            override fun join(invite: String, name: String, progress: (Int, String, Int, Int) -> Unit): Int = error("no join")
            override fun cancelJoin() {}
            override fun ping(slot: Int, identity: String) = 0L
            override fun useExit(slot: Int, identity: String) {}
            override fun exitOff(slot: Int) {}
            override fun forget(slot: Int) {}
            override fun leave(slot: Int) {}
            override fun diagnose() = "{}"
            override fun changes(slot: Int) = "[]"
            override fun setNames(slot: Int, on: Boolean) {}
            override fun setPublicNames(slot: Int, on: Boolean) {}
            override fun setHttpsOnly(slot: Int, on: Boolean) {}
            override fun setPortMapping(slot: Int, on: Boolean) {}
            override fun create(network: String, name: String, seed: ByteArray) = io.juist.app.core.Founded(0, "", "nid:abc")
            override fun invite(slot: Int, minutes: Int, admin: String, events: io.juist.app.core.InviteEvents) {}
            override fun cancelInvite() {}
            override fun admit(seed: ByteArray) {}
            override fun refuse() {}
            override fun remove(slot: Int, identity: String, seed: ByteArray, lastVoucher: Boolean) = true
            override fun grant(slot: Int, identity: String, role: String, on: Boolean, seed: ByteArray, lastVoucher: Boolean) = true
        })
        Juist.refresh()
    }

    /** In a network already, a link opened asks to join another, and joins nothing until tapped. */
    @Test
    fun aLinkInANetworkAsksToJoinAnother() {
        attach(File("../../mobile/testdata/view.json").readText())
        val opened = mutableStateOf<String?>(link)
        show(opened)
        compose.onNodeWithText(text(R.string.confirm_link_opened)).assertIsDisplayed()
        assertEquals(JoinState.Idle, Juist.join.value)
        compose.runOnUiThread { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithText(text(R.string.another_title)).assertIsDisplayed()
    }

    /** In two networks, the app opens at their list, and a network's status has the way back to it. */
    @Test
    fun severalNetworksAreListed() {
        attach(twoNetworks())
        show(mutableStateOf(null))
        compose.onNodeWithText(text(R.string.section_networks)).assertIsDisplayed()
        compose.onNodeWithText("office").assertIsDisplayed().performClick()
        compose.onNodeWithText(text(R.string.section_this_device)).assertIsDisplayed()
        compose.runOnUiThread { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithText(text(R.string.action_join_another)).assertIsDisplayed()
    }

    /** A network left beside two others leaves its screen for the list. */
    @Test
    fun aNetworkLeftLeavesItsScreen() {
        val three = twoNetworks().dropLast(1) + """,{"slot":3,"state":"connected","network":"lab"}]"""
        attach(three)
        show(mutableStateOf(null))
        compose.onNodeWithText("office").performClick()
        compose.onNodeWithText(text(R.string.section_this_device)).assertIsDisplayed()
        status = three.replace("""{"slot":2,"state":"waiting"""", """{"slot":2,"state":"none"""")
        Juist.refresh()
        compose.waitForIdle()
        compose.onNodeWithText(text(R.string.section_networks)).assertIsDisplayed()
    }

    /** At the most networks a phone joins, a link opened changes nothing. */
    @Test
    fun aLinkAtTheMostNetworksIsIgnored() {
        val home = File("../../mobile/testdata/view.json").readText().trim().dropLast(1)
        attach((0 until MAX_NETWORKS).joinToString(",", "[", "]") { """$home,"slot":$it}""" })
        show(mutableStateOf(link))
        compose.waitForIdle()
        assertEquals(0, compose.onAllNodesWithTextCount(text(R.string.confirm_link_opened)))
    }

    /** Every screen survives a recreated activity, and one an earlier app saved is read. */
    @Test
    fun routesSurviveBeingSaved() {
        for (r in listOf(Route.Welcome, Route.Another, Route.Networks, Route.Scan, Route.Code, Route.Confirm(link),
            Route.Confirm(link, fromElsewhere = true), Route.Joining, Route.Status(), Route.Status(2), Route.MemberOf("nid:abc"),
            Route.MemberOf("nid:abc", 3), Route.About, Route.Licenses, Route.Details(1), Route.Create, Route.Backup(1),
            Route.Backup(1, fresh = true), Route.Invite(2))) {
            assertEquals(r, decode(encode(r)))
        }
        assertEquals(Route.Status(0), decode("Status"))
        assertEquals(Route.Details(0), decode("Details"))
        assertEquals(Route.MemberOf("nid:abc", 0), decode("member:nid:abc"))
    }

    /** An invite link opens the app; another link or intent does not. */
    @Test
    fun onlyAnInviteLinkIsTaken() {
        assertEquals(link, inviteLinkOf(Intent(Intent.ACTION_VIEW, Uri.parse(link))))
        assertNull(inviteLinkOf(Intent(Intent.ACTION_VIEW, Uri.parse("https://juist.nning.io/"))))
        assertNull(inviteLinkOf(Intent(Intent.ACTION_MAIN)))
        assertNull(inviteLinkOf(null))
    }

    private fun androidx.compose.ui.test.junit4.AndroidComposeTestRule<*, *>.onAllNodesWithTextCount(s: String) =
        onAllNodes(androidx.compose.ui.test.hasText(s)).fetchSemanticsNodes().size

    /**
     * Slot 0's network just founded with the admin key nid:abc, whose key file the phone holds, not
     * openable here; its view names no admins, as one whose mesh is not up yet.
     */
    private fun founding(key: ByteArray = "not sealed".toByteArray()) {
        val home = File("../../mobile/testdata/view.json").readText().trim().dropLast(1)
        attach("""[$home,"slot":0]""")
        File(compose.activity.noBackupFilesDir, "admin").apply { mkdirs() }.resolve("nid_abc.key").writeBytes(key)
        Juist.founded(io.juist.app.core.Founded(0, "juist-break-glass-1.AAAA.BBBB", admin = "nid:abc"))
    }

    private fun back() {
        compose.runOnUiThread { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.waitForIdle()
    }

    /**
     * A network just founded shows its break-glass secret over everything, once: back asks first,
     * then leaves it for good.
     */
    @Test
    fun aFreshBackupShowsTheSecretOnce() {
        founding()
        try {
            show(mutableStateOf(null))
            compose.onNodeWithText("juist-break-glass-1.AAAA.BBBB", substring = true).assertExists()
            back()
            compose.onNodeWithText(text(R.string.backup_leave_body)).assertIsDisplayed()
            compose.onNodeWithText(text(R.string.backup_stay)).performClick()
            assertEquals("juist-break-glass-1.AAAA.BBBB", Juist.founded.value?.breakGlass)
            // The top bar's arrow asks as well.
            compose.onNodeWithContentDescription(text(R.string.action_back)).performClick()
            compose.onNodeWithText(text(R.string.backup_leave_body)).assertIsDisplayed()
            compose.onNodeWithText(text(R.string.backup_stay)).performClick()
            assertEquals("juist-break-glass-1.AAAA.BBBB", Juist.founded.value?.breakGlass)
            back()
            compose.onNodeWithText(text(R.string.backup_leave)).performClick()
            compose.waitForIdle()
            assertNull(Juist.founded.value)
            assertEquals(0, compose.onAllNodesWithTextCount("juist-break-glass-1.AAAA.BBBB"))
        } finally {
            Juist.founded(null)
        }
    }

    /** Once the secret is copied, back leaves without asking. */
    @Test
    fun aCopiedSecretLeavesWithoutAsking() {
        founding()
        try {
            show(mutableStateOf(null))
            compose.onNodeWithText(text(R.string.action_copy)).performScrollTo().performClick()
            compose.waitForIdle()
            back()
            assertNull(Juist.founded.value)
        } finally {
            Juist.founded(null)
        }
    }

    /** The backup takes the key the founding named, without the network's view; one damaged says it is lost. */
    @Test
    fun aDamagedKeySaysItIsLost() = keySaysItIsLost("not sealed".toByteArray())

    /** A key file of the right version but short of its tag is damaged too. */
    @Test
    fun aKeyShortOfItsTagSaysItIsLost() = keySaysItIsLost(byteArrayOf(1) + ByteArray(20))

    private fun keySaysItIsLost(key: ByteArray) {
        founding(key)
        try {
            show(mutableStateOf(null))
            compose.onNodeWithText(text(R.string.backup_copy_line)).performScrollTo().performClick()
            compose.waitUntil(5_000) {
                org.robolectric.shadows.ShadowToast.getTextOfLatestToast() == text(R.string.admin_key_lost)
            }
        } finally {
            Juist.founded(null)
        }
    }

    /** A link opened while the backup shows is there once it is left. */
    @Test
    fun aLinkOpenedDuringTheBackupWaits() {
        founding()
        try {
            show(mutableStateOf(link))
            back()
            compose.onNodeWithText(text(R.string.backup_leave)).performClick()
            compose.onNodeWithText(text(R.string.confirm_link_opened)).assertIsDisplayed()
        } finally {
            Juist.founded(null)
        }
    }

    /** Two secure screens overlapping keep the window secure until both are gone. */
    @Test
    fun overlappingSecureScreensStaySecure() {
        val both = mutableStateOf(true)
        val one = mutableStateOf(true)
        compose.setContent {
            if (one.value) io.juist.app.ui.Secure()
            if (both.value) io.juist.app.ui.Secure()
        }
        fun secure() = compose.activity.window.attributes.flags and android.view.WindowManager.LayoutParams.FLAG_SECURE != 0
        compose.waitForIdle()
        assertEquals(true, secure())
        both.value = false
        compose.waitForIdle()
        assertEquals(true, secure())
        one.value = false
        compose.waitForIdle()
        assertEquals(false, secure())
    }

    /** Taking the last voucher asks first, and changes nothing unconfirmed. */
    @Test
    fun theLastVoucherIsTakenOnlyOnceConfirmed() {
        val calls = mutableListOf<Pair<String, Boolean>>()
        compose.setContent {
            JuistTheme {
                io.juist.app.ui.screens.AdminSection(setOf("voucher"), isSelf = false, enabled = true,
                    onRole = { r, on -> calls += r to on }, onRemove = {}, lastVoucher = true)
            }
        }
        compose.onNodeWithText(text(R.string.role_voucher)).performClick()
        compose.onNodeWithText(text(R.string.last_voucher_title)).assertIsDisplayed()
        assertEquals(emptyList<Pair<String, Boolean>>(), calls)
        compose.onNodeWithText(text(R.string.action_revoke)).performClick()
        assertEquals(listOf("voucher" to false), calls)
    }
}

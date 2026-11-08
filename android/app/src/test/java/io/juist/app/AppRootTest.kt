package io.juist.app

import android.content.Intent
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
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
            override fun setHttpsOnly(slot: Int, on: Boolean) {}
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
            Route.MemberOf("nid:abc", 3), Route.About, Route.Licenses, Route.Details(1))) {
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
}

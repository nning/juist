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
import io.juist.app.core.CoreCalls
import io.juist.app.core.JoinState
import io.juist.app.core.Juist
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

    /** In a network already, a link opened changes nothing. */
    @Test
    fun aLinkInANetworkIsIgnored() {
        Juist.attached(object : CoreCalls {
            override fun status() = File("../../mobile/testdata/view.json").readText()
            override fun join(invite: String, name: String, progress: (Int, String, Int, Int) -> Unit) = error("no join")
            override fun cancelJoin() {}
            override fun ping(identity: String) = 0L
            override fun useExit(identity: String) {}
            override fun exitOff() {}
            override fun forget() {}
        })
        Juist.refresh()
        show(mutableStateOf(link))
        compose.waitForIdle()
        assertEquals(0, compose.onAllNodesWithTextCount(text(R.string.confirm_link_opened)))
        assertEquals(JoinState.Idle, Juist.join.value)
    }

    /** Every screen survives a recreated activity. */
    @Test
    fun routesSurviveBeingSaved() {
        for (r in listOf(Route.Welcome, Route.Scan, Route.Code, Route.Confirm(link), Route.Confirm(link, fromElsewhere = true),
            Route.Joining, Route.Status, Route.MemberOf("nid:abc"), Route.About, Route.Licenses)) {
            assertEquals(r, decode(encode(r)))
        }
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

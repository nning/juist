package io.juist.app

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import io.juist.app.core.Reach
import io.juist.app.ui.screens.MemberScreen
import io.juist.app.ui.screens.PingResult
import io.juist.app.ui.theme.JuistTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MemberScreenTest {
    @get:Rule
    val compose = createAndroidComposeRule<ComponentActivity>()

    private fun text(id: Int) = compose.activity.getString(id)

    private fun show(reach: Reach) = compose.setContent {
        JuistTheme {
            MemberScreen(
                sampleView.members[1].copy(reach = reach), on = true, pings = listOf(PingResult(157.3)),
                pinging = false, onPing = {}, onOpen = {}, onBack = {},
            )
        }
    }

    /** An outdated member answers a ping but no other app: the screen says so, and opens no browser. */
    @Test
    fun anOutdatedMemberPromisesNoApp() {
        show(Reach.Outdated)
        compose.onNodeWithText(text(R.string.ping_about_outdated)).assertExists()
        compose.onNodeWithText(text(R.string.ping_about)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.action_ping)).assertIsEnabled()
        compose.onNodeWithText(text(R.string.action_open_web)).assertIsNotEnabled()
    }

    @Test
    fun aDirectMemberOpensInTheBrowser() {
        show(Reach.Direct)
        compose.onNodeWithText(text(R.string.ping_about)).assertExists()
        compose.onNodeWithText(text(R.string.action_open_web)).assertIsEnabled()
    }
}

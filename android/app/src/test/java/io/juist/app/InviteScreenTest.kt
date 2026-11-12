package io.juist.app

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.unit.height
import io.juist.app.core.InviteState
import io.juist.app.ui.screens.InviteScreen
import io.juist.app.ui.theme.JuistTheme
import kotlin.math.abs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(qualifiers = "de-w360dp-h1600dp-hdpi", fontScale = 2f)
class InviteScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private fun show(state: InviteState) = compose.setContent {
        JuistTheme { InviteScreen(state, onShare = {}, onSame = {}, onDifferent = {}, onClose = {}) }
    }

    /** The words' two answers stand side by side at one height, however each label wraps. */
    @Test fun theAnswersAreOfOneHeight() {
        show(InviteState.Comparing("ample ribbon tundra velvet", "laptop"))
        val same = compose.onNodeWithText(compose.activity.getString(R.string.invite_same)).getUnclippedBoundsInRoot()
        val different = compose.onNodeWithText(compose.activity.getString(R.string.invite_different)).getUnclippedBoundsInRoot()
        assertEquals("same $same, different $different", same.height, different.height)
    }

}

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(qualifiers = "de-w360dp-h800dp-hdpi")
class InviteScreenCentreTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    /** A short line, as while a device is admitted, stands in the middle of the screen. */
    @Test fun aShortLineIsCentred() {
        compose.setContent {
            JuistTheme { InviteScreen(InviteState.Admitting("iophon"), onShare = {}, onSame = {}, onDifferent = {}, onClose = {}) }
        }
        val root = compose.onRoot().getUnclippedBoundsInRoot()
        val line = compose.onNodeWithText(compose.activity.getString(R.string.invite_admitting, "iophon")).getUnclippedBoundsInRoot()
        val off = (line.left + line.right - root.left - root.right).value / 2
        assertTrue("the line $line is ${off}dp off the middle of $root", abs(off) < 1f)
    }

    /** Once the device joined, the screen hands back to the network, naming it once. */
    @Test fun aJoinedDeviceLeavesTheScreen() {
        var joined: String? = null
        compose.setContent {
            JuistTheme {
                InviteScreen(InviteState.Joined("iophon"), onShare = {}, onSame = {}, onDifferent = {}, onClose = {},
                    onJoined = { joined = it })
            }
        }
        compose.waitForIdle()
        assertEquals("iophon", joined)
    }
}

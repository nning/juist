package io.juist.app

import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.captureRoboImage
import io.juist.app.core.Connection
import io.juist.app.core.JoinState
import io.juist.app.core.JoinStep
import io.juist.app.core.Tunnels
import io.juist.app.ui.LocalInviteChecks
import io.juist.app.ui.LocalNow
import io.juist.app.ui.screens.JoiningScreen
import io.juist.app.ui.screens.StatusScreen
import io.juist.app.ui.screens.WelcomeScreen
import io.juist.app.ui.theme.JuistTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** The phone in the tour, website/video: the network of its terminal scene, every device reached directly. */
@RunWith(RobolectricTestRunner::class)
@Config(qualifiers = "en-w360dp-h800dp-night-xxhdpi")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class TourShots {
    @get:Rule
    val compose = createComposeRule()

    private fun shot(name: String, content: @Composable () -> Unit) {
        compose.setContent {
            CompositionLocalProvider(LocalNow provides NOW, LocalInviteChecks provides FakeInviteChecks) {
                JuistTheme { content() }
            }
        }
        compose.onRoot().captureRoboImage("../../website/video/phone/$name.png")
    }

    private val none = {}

    @Test fun welcome() = shot("welcome") { WelcomeScreen(none, none, none) }

    @Test fun joining() = shot("joining") {
        JoiningScreen(JoinState.Running(JoinStep.Compare, words = listOf("talon", "saturday", "skydive", "bifocals")), none, none)
    }

    @Test fun connected() = shot("status") { StatusScreen(Connection.On(tourView), none, none, {}, none, none) }
}

private val tourView = sampleView.copy(
    members = sampleView.members.take(2),
    tunnels = Tunnels(live = 2, total = 2, checked = NOW - 20),
    alarms = emptyList(),
)

package io.juist.app

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import io.juist.app.core.ExitView
import io.juist.app.ui.screens.ExitSection
import io.juist.app.ui.theme.JuistTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ExitSectionTest {
    @get:Rule
    val compose = createAndroidComposeRule<ComponentActivity>()

    private val chosen = mutableListOf<String?>()

    private fun show(exit: ExitView, on: Boolean = true) = compose.setContent {
        JuistTheme { ExitSection(exit, on, onExit = { chosen += it }, onVpnSettings = {}) }
    }

    // The first: a member reached directly says so too.
    private fun direct() = compose.onAllNodesWithText(compose.activity.getString(R.string.exit_direct))[0]

    /** A tap on an exit node chooses it, and one on direct chooses none. */
    @Test
    fun aTapChooses() {
        val exit = exitView.exit!!
        show(exit)
        val other = exit.offering.first { it.identity != exit.node }
        compose.onNodeWithText(other.name).performClick()
        direct().performClick()
        assertEquals(listOf(other.identity, null), chosen)
    }

    /** Off, nothing can be chosen. */
    @Test
    fun offNothingIsChosen() {
        show(exitView.exit!!, on = false)
        direct().assertIsNotEnabled()
        direct().performClick()
        assertEquals(emptyList<String?>(), chosen)
    }

    /** An exit node chosen and no longer on offer stays listed, chosen, and says why it is refused. */
    @Test
    fun aChoiceNoLongerOfferedStays() {
        show(ExitView(node = "nid:GONE", name = "old-vps", refused = "old-vps no longer serves as an exit node"))
        compose.onNodeWithText("old-vps").assertIsSelected()
        compose.onNodeWithText(compose.activity.getString(R.string.exit_refused, "old-vps no longer serves as an exit node"))
            .assertExists()
    }
}

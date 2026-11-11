package io.juist.app

import io.juist.app.core.InviteState
import io.juist.app.ui.screens.AdminSection
import io.juist.app.ui.screens.BackupScreen
import io.juist.app.ui.screens.CreateScreen
import io.juist.app.ui.screens.InviteScreen
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performScrollTo
import com.github.takahirom.roborazzi.captureRoboImage
import io.juist.app.core.Connection
import io.juist.app.core.JoinState
import io.juist.app.core.JoinStep
import io.juist.app.core.OffReason
import io.juist.app.core.Reach
import io.juist.app.ui.LocalInviteChecks
import io.juist.app.ui.LocalNow
import io.juist.app.ui.screens.AboutScreen
import io.juist.app.ui.screens.CodeScreen
import io.juist.app.ui.screens.ConfirmScreen
import io.juist.app.ui.screens.DetailsScreen
import io.juist.app.ui.screens.JoiningScreen
import io.juist.app.ui.screens.MemberScreen
import io.juist.app.ui.screens.NetworksScreen
import io.juist.app.ui.screens.PingResult
import io.juist.app.ui.screens.ScanScreen
import io.juist.app.ui.screens.StatusScreen
import io.juist.app.ui.screens.WelcomeScreen
import io.juist.app.ui.theme.JuistTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * Every screen, rendered without a device: each subclass is one of four
 * variants, which between them show both themes, both languages, and 200 %
 * font scale in each theme. `make android-screenshots` records them into
 * android/app/screenshots, and `make android-check` fails where one changed.
 */
@GraphicsMode(GraphicsMode.Mode.NATIVE)
abstract class Screens(private val variant: String) {
    @get:Rule
    val compose = createComposeRule()

    private fun shot(name: String, scrollTo: String? = null, content: @Composable () -> Unit) {
        compose.setContent {
            CompositionLocalProvider(LocalNow provides NOW, LocalInviteChecks provides FakeInviteChecks) {
                JuistTheme { content() }
            }
        }
        if (scrollTo != null) compose.onNodeWithText(scrollTo, substring = true).performScrollTo()
        compose.onRoot().captureRoboImage("screenshots/${name}_$variant.png")
    }

    private val none = {}

    @Test fun welcome() = shot("welcome") { WelcomeScreen(none, none, none) }

    @Test fun joinAnother() = shot("welcome_another") { WelcomeScreen(none, none, none, onBack = none) }

    @Test fun networks() = shot("networks") {
        NetworksScreen(Connection.On(listOf(sampleView, officeView)), none, none, {}, none, none)
    }

    @Test fun scanAsksForTheCamera() = shot("scan") {
        ScanScreen(granted = false, denied = false, onAllow = none, onInvite = {}, onCode = none, onBack = none) { _, _ -> }
    }

    @Test fun codeCompletesAWord() = shot("code") { CodeScreen({}, none, initial = "650-billiard-vir", focus = false) }

    @Test fun codeSaysAWordIsMisplaced() = shot("code_error") {
        CodeScreen({}, none, initial = "42-tolerance-drumbeat ", focus = false)
    }

    @Test fun confirm() = shot("confirm") { ConfirmScreen("juist:abc@192.0.2.1:41642", "pixel-8", {}, none) }

    @Test fun confirmALinkOpenedElsewhere() = shot("confirm_opened") {
        ConfirmScreen("juist:abc@192.0.2.1:41642", "pixel-8", {}, none, fromElsewhere = true)
    }

    @Test fun scanWithTheCameraRefused() = shot("scan_denied") {
        ScanScreen(granted = false, denied = true, onAllow = none, onInvite = {}, onCode = none, onBack = none) { _, _ -> }
    }

    @Test fun joiningComparesWords() = shot("joining_words") {
        JoiningScreen(
            JoinState.Running(JoinStep.Compare, words = listOf("talon", "saturday", "skydive", "bifocals")), none, none,
        )
    }

    @Test fun joiningWaitsForVotes() = shot("joining_votes") {
        JoiningScreen(
            JoinState.Running(JoinStep.Waiting, relayed = true, words = listOf("talon", "saturday", "skydive", "bifocals"), votes = 1, quorum = 2),
            none, none,
        )
    }

    @Test fun joinFailed() = shot("joining_failed") {
        JoiningScreen(JoinState.Failed("the inviting device went away: enroll: reading a frame: EOF"), none, none)
    }

    @Test fun connected() = shot("status") { StatusScreen(Connection.On(sampleView), none, none, {}, none, none) }

    @Test fun limited() = shot("status_limited") { StatusScreen(Connection.On(limitedView), none, none, {}, none, none) }

    @Test fun forked() = shot("status_alarm") { StatusScreen(Connection.On(forkedView), none, none, {}, none, none) }

    @Test fun privateDns() = shot("status_private_dns") { StatusScreen(Connection.On(privateDnsView), none, none, {}, none, none) }

    @Test fun removed() = shot("status_removed") { StatusScreen(Connection.On(removedView), none, none, {}, none, none) }

    @Test fun off() = shot("status_off") {
        StatusScreen(Connection.Off(sampleView, OffReason.Revoked), none, none, {}, none, none)
    }

    @Test fun failed() = shot("status_failed") {
        StatusScreen(
            Connection.Failed("home/node.keys: opening the sealed key material: KeyStoreException", sampleView),
            none, none, {}, none, none,
        )
    }

    @Test fun throughAnExitNode() = shot("status_exit") { StatusScreen(Connection.On(exitView), none, none, {}, none, none) }

    @Test fun anExitNodeRefused() = shot("status_exit_refused") {
        StatusScreen(Connection.On(exitRefusedView), none, none, {}, none, none)
    }

    @Test fun joinFailedByCode() = shot("joining_failed_code") {
        JoiningScreen(
            JoinState.Failed("no device on this network has an invite numbered 650", byCode = true), none, none,
        )
    }

    @Test fun starting() = shot("status_starting") { StatusScreen(Connection.Starting(sampleView), none, none, {}, none, none) }

    @Test fun member() = shot("member") {
        MemberScreen(
            sampleView.members[2], on = true,
            pings = listOf(PingResult(23.4), PingResult(null, "no answer within 5s"), PingResult(31.0)),
            pinging = false, onPing = none, onOpen = {}, onBack = none,
        )
    }

    @Test fun memberWithServices() = shot("member_services") {
        MemberScreen(servicesMember, on = true, pings = emptyList(), pinging = false, onPing = none, onOpen = {}, onBack = none)
    }

    @Test fun details() = shot("details") {
        DetailsScreen(detailsView, on = true, changes = sampleChanges, diagnosis = sampleDiagnosis, onNames = {},
            onPublicNames = {}, onHttpsOnly = {}, onPortMapping = {}, onCopyReport = none, onBack = none)
    }

    @Test fun memberRelayedByTailscale() = shot("member_tailscale") {
        val m = sampleView.members.first { it.reach == Reach.Relay }.copy(relay = "Tailscale Frankfurt", relayPublic = true)
        MemberScreen(m, on = true, pings = emptyList(), pinging = false, onPing = none, onOpen = {}, onBack = none)
    }

    /** On HTTPS alone, Tailscale's servers serve on 443: no "none on 443". */
    @Test fun detailsPublicDerp() {
        shot("details_public_derp", scrollTo = "Tailscale Frankfurt") {
            val v = detailsView.copy(
                settings = detailsView.settings.copy(httpsOnly = true),
                details = detailsView.details.copy(schema = 24, appSchema = 24, relays = 0, installed = 0,
                    home = "Tailscale Frankfurt", publicDerp = true),
            )
            DetailsScreen(v, on = true, changes = sampleChanges, diagnosis = sampleDiagnosis, onNames = {},
                onPublicNames = {}, onHttpsOnly = {}, onPortMapping = {}, onCopyReport = none, onBack = none)
        }
        val none443 = org.robolectric.RuntimeEnvironment.getApplication().getString(R.string.relays_https_none)
        compose.onNodeWithText(none443, substring = true).assertDoesNotExist()
    }

    @Test fun create() = shot("create") { CreateScreen("pixel-8", busy = false, onCreate = { _, _ -> }, onBack = none) }

    @Test fun backup() = shot("backup") {
        BackupScreen("juist-break-glass-1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAA",
            onCopyBreakGlass = none, onCopyLine = none, onSaveFile = {}, onDone = none)
    }

    @Test fun inviteOffered() = shot("invite") {
        InviteScreen(InviteState.Offered("650-ample-ribbon", "juist:AAAA.198.51.100.7:41642"), onShare = {}, onSame = none,
            onDifferent = none, onClose = none)
    }

    @Test fun inviteComparing() = shot("invite_compare") {
        InviteScreen(InviteState.Comparing("ample ribbon tundra velvet", "laptop"), onShare = {}, onSame = none,
            onDifferent = none, onClose = none)
    }

    @Test fun memberAsAdmin() = shot("member_admin") {
        MemberScreen(sampleView.members[2], on = true, pings = emptyList(), pinging = false, onPing = none, onOpen = {}, onBack = none,
            admin = { AdminSection(setOf("relay"), isSelf = false, enabled = true, onRole = { _, _ -> }, onRemove = none) })
    }

    @Test fun about() = shot("about") { AboutScreen("0+8f4f2b0", none, none, none, none) }
}

// At 200 %, a screen is drawn twice as tall, so that it shows what a phone scrolls to.
private const val PHONE = "w360dp-h800dp-hdpi"
private const val NIGHT = "w360dp-h800dp-night-hdpi"
private const val TALL = "w360dp-h1600dp-hdpi"
private const val TALL_NIGHT = "w360dp-h1600dp-night-hdpi"

@RunWith(RobolectricTestRunner::class)
@Config(qualifiers = "en-$PHONE")
class DayEnglish : Screens("day_en")

@RunWith(RobolectricTestRunner::class)
@Config(qualifiers = "de-$NIGHT")
class NightGerman : Screens("night_de")

@RunWith(RobolectricTestRunner::class)
@Config(qualifiers = "de-$TALL", fontScale = 2f)
class DayGermanLarge : Screens("day_de_200")

@RunWith(RobolectricTestRunner::class)
@Config(qualifiers = "en-$TALL_NIGHT", fontScale = 2f)
class NightEnglishLarge : Screens("night_en_200")

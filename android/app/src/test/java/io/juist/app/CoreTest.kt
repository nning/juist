package io.juist.app

import io.juist.app.core.CodeProblem
import io.juist.app.core.FreshState
import io.juist.app.core.InviteCode
import io.juist.app.core.JoinState
import io.juist.app.core.JoinStep
import io.juist.app.core.PublicName
import io.juist.app.core.Reach
import io.juist.app.core.Severity
import io.juist.app.core.State
import io.juist.app.core.joinStep
import io.juist.app.core.parseView
import io.juist.app.ui.screens.suggestedName
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CoreTest {
    /** mobile/testdata/view.json, which the Go side's test holds viewOf to. */
    @Test
    fun readsTheViewTheCoreWrites() {
        val v = parseView(File("../../mobile/testdata/view.json").readText())
        assertEquals(State.Connected, v.state)
        assertEquals("fd00::5", v.self.v6)
        assertEquals(listOf(Reach.Direct, Reach.Relay, Reach.Sought, Reach.Silent), v.members.map { it.reach })
        assertEquals(listOf("", "anna", "", ""), v.members.map { it.relay })
        assertEquals(FreshState.Fresh, v.fresh.state)
        assertEquals(listOf("epoch", "silent"), v.alarms.map { it.kind })
        assertEquals(Severity.Warn, v.alarms[0].severity)
        val anna = v.members.first { it.name == "anna" }
        assertEquals(listOf("wiki.example.org", "game.example.org:25565"), anna.published)
        assertEquals(listOf("wiki.example.org"), anna.membersOnly)
        assertEquals(listOf("192.168.7.0/24"), anna.subnets)
        assertEquals(22, anna.build)
        assertEquals(true, v.settings.names)
        assertEquals(true, v.settings.publicNames)
        assertEquals(PublicName("rss.example.org", "anna", "anna is not reachable"), v.names?.public?.single())
        assertEquals(22, v.details.schema)
        assertEquals("anna", v.details.subnets.single().router)
        assertTrue(v.details.publicDerp)
    }

    @Test
    fun readsARelayOfTailscales() {
        val json = File("../../mobile/testdata/view.json").readText()
            .replace("\"relay\": \"anna\"", "\"relay\": \"Tailscale Frankfurt\", \"relayPublic\": true")
        val bert = parseView(json).members.first { it.reach == Reach.Relay }
        assertEquals("Tailscale Frankfurt", bert.relay)
        assertTrue(bert.relayPublic)
    }

    @Test
    fun readsWhatItDoesNotKnowAsUnknown() {
        val v = parseView("""{"state":"elsewhere","self":{"reach":"sideways"},"extra":1}""")
        assertEquals(State.Unknown, v.state)
        assertEquals(Reach.Unknown, v.self.reach)
    }

    @Test
    fun readsAnOutdatedMember() {
        assertEquals(Reach.Outdated, parseView("""{"self":{"reach":"outdated"}}""").self.reach)
    }

    @Test
    fun saysWhatIsWrongWithACode() {
        val c = FakeInviteChecks
        assertNull(InviteCode.problem(c, "42 Drumbeat tolerance-GLUCOSE"))
        assertEquals(CodeProblem.Number, InviteCode.problem(c, "1000-drumbeat"))
        assertEquals(CodeProblem.WrongPlace("tolerance"), InviteCode.problem(c, "42-tolerance-drumbeat-glucose"))
        assertEquals(CodeProblem.UnknownWord("drumbeet"), InviteCode.problem(c, "42-drumbeet"))
        assertEquals(CodeProblem.Incomplete, InviteCode.problem(c, "42-drumbeat-tolerance"))
        assertEquals("42-drumbeat-tolerance-glucose", InviteCode.canonical(InviteCode.parts(" 42  drumbeat-Tolerance glucose ")))
    }

    @Test
    fun followsAJoinsEvents() {
        var s: JoinState = JoinState.Running(JoinStep.Starting)
        s = joinStep(s, 1, "", 0, 0)
        s = joinStep(s, 2, "relay", 0, 0)
        assertEquals(JoinState.Running(JoinStep.Connected, relayed = true), s)
        s = joinStep(s, 5, "talon-saturday-skydive-bifocals", 0, 0)
        assertEquals(listOf("talon", "saturday", "skydive", "bifocals"), (s as JoinState.Running).words)
        assertEquals(s, joinStep(s, 3, "", 0, 0)) // the admin still deciding
        s = joinStep(s, 3, "", 1, 2)
        assertEquals(JoinStep.Waiting, (s as JoinState.Running).step)
        assertEquals(2, s.quorum)
    }

    @Test
    fun suggestsANameFromThePhones() {
        assertEquals("pixel-8-pro", suggestedName("Pixel 8 Pro"))
        assertEquals("phone", suggestedName(null))
        assertEquals("phone", suggestedName("☃"))
    }
}

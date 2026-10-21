package io.juist.app

import io.juist.app.core.JoinState
import io.juist.app.core.JoinStep
import io.juist.app.core.Pace
import io.juist.app.core.holdsMulticast
import org.junit.Assert.assertEquals
import org.junit.Test

class PaceTest {
    @Test
    fun savesWhileTheScreenIsOffTheDeviceDozesOrBatterySaverIsOn() {
        assertEquals(false, Pace().saving)
        assertEquals(true, Pace(interactive = false).saving)
        assertEquals(true, Pace(idle = true).saving)
        assertEquals(true, Pace(powerSave = true).saving)
    }

    /** Mobile data costs radio time as well as money: only the app in front keeps the pace. */
    @Test
    fun savesOnAMeteredNetworkWhileTheAppIsNotInFront() {
        assertEquals(true, Pace(metered = true).saving)
        assertEquals(false, Pace(metered = true, inFront = true).saving)
        assertEquals(false, Pace(inFront = false).saving)
        assertEquals(true, Pace(interactive = false, metered = true, inFront = true).saving)
    }

    /** Every multicast packet on the Wi-Fi wakes a phone holding the lock. */
    @Test
    fun theMulticastLockIsHeldWhileNotSavingOrJoining() {
        val off = Pace(interactive = false)
        assertEquals(true, holdsMulticast(Pace(), JoinState.Idle))
        assertEquals(false, holdsMulticast(off, JoinState.Idle))
        assertEquals(true, holdsMulticast(off, JoinState.Running(JoinStep.Starting)))
    }
}

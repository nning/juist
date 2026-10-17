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

    /** Every multicast packet on the Wi-Fi wakes a phone holding the lock. */
    @Test
    fun theMulticastLockIsHeldWhileNotSavingOrJoining() {
        val off = Pace(interactive = false)
        assertEquals(true, holdsMulticast(Pace(), JoinState.Idle))
        assertEquals(false, holdsMulticast(off, JoinState.Idle))
        assertEquals(true, holdsMulticast(off, JoinState.Running(JoinStep.Starting)))
    }
}

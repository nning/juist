package io.juist.app

import io.juist.app.core.Connection
import io.juist.app.core.NetworkView
import io.juist.app.core.State
import io.juist.app.core.TileAction
import io.juist.app.core.tileAction
import io.juist.app.core.tileState
import io.juist.app.core.tileSubtitle
import android.service.quicksettings.Tile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class TileTest {
    /** The tile turns off what runs, turns on a network Android may route, and opens the app for the rest. */
    @Test
    fun aTapDoesWhatTheSwitchWould() {
        assertEquals(TileAction.TurnOff, tileAction(Connection.On(sampleView), needsConsent = false))
        assertEquals(TileAction.TurnOff, tileAction(Connection.Starting(sampleView), needsConsent = false))
        assertEquals(TileAction.TurnOn, tileAction(Connection.Off(sampleView), needsConsent = false))
        assertEquals(TileAction.OpenApp, tileAction(Connection.Off(sampleView), needsConsent = true))
        assertEquals(TileAction.OpenApp, tileAction(Connection.Off(null), needsConsent = false))
        assertEquals(TileAction.OpenApp, tileAction(Connection.Off(NetworkView(state = State.None)), needsConsent = false))
    }

    /** Android delivers no tap to an unavailable tile, so one in no network stays tappable, to open the app. */
    @Test
    fun aTileInNoNetworkTakesTaps() {
        assertNotEquals(Tile.STATE_UNAVAILABLE, tileState(Connection.Off(null)))
        assertEquals(R.string.state_none, tileSubtitle(Connection.Off(null)))
        assertEquals(R.string.state_vpn_off, tileSubtitle(Connection.Off(sampleView)))
        assertEquals(Tile.STATE_ACTIVE, tileState(Connection.On(sampleView)))
    }
}

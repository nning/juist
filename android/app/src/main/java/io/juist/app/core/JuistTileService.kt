package io.juist.app.core

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import io.juist.app.MainActivity
import io.juist.app.R
import io.juist.app.ui.stateLabel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** A Quick Settings tile that turns the VPN on and off as the app's switch does. */
class JuistTileService : TileService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var watcher: Job? = null

    override fun onStartListening() {
        watcher?.cancel()
        watcher = scope.launch { Juist.connection.collect(::show) }
    }

    override fun onStopListening() {
        watcher?.cancel()
        watcher = null
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onClick() {
        when (tileAction(Juist.connection.value, Juist.consentIntent(this) != null)) {
            TileAction.TurnOff -> Juist.disconnect(this)
            TileAction.TurnOn -> Juist.connect(this)
            TileAction.OpenApp -> openApp()
        }
    }

    // The Intent form runs below API 34 alone, where the PendingIntent form does not exist.
    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun show(c: Connection) {
        val tile = qsTile ?: return
        tile.state = tileState(c)
        tile.label = networkNames(c.views).ifEmpty { getString(R.string.app_name) }
        tile.subtitle = getString(tileSubtitle(c))
        tile.updateTile()
    }
}

/** The tile's state; never unavailable, as Android delivers no tap to that. */
internal fun tileState(c: Connection): Int =
    if (c is Connection.On || c is Connection.Starting) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE

internal fun tileSubtitle(c: Connection): Int = when (c) {
    is Connection.On -> stateLabel(c.worstState ?: c.view.state)
    is Connection.Starting -> R.string.state_starting
    is Connection.Failed -> R.string.state_failed
    is Connection.Off -> if (c.networks.isEmpty()) R.string.state_none else R.string.state_vpn_off
}

internal enum class TileAction { TurnOn, TurnOff, OpenApp }

/**
 * What a tap on the tile does: turn off what is on, turn on a network
 * Android may route, and open the app where it has to ask or join first.
 */
internal fun tileAction(c: Connection, needsConsent: Boolean): TileAction = when {
    c is Connection.On || c is Connection.Starting -> TileAction.TurnOff
    c.networks.isEmpty() || needsConsent -> TileAction.OpenApp
    else -> TileAction.TurnOn
}

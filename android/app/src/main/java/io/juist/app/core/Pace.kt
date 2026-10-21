package io.juist.app.core

/**
 * What the phone is doing, which the core's pace follows: it saves battery
 * while the screen is off, the phone dozes or battery saver is on, and on a
 * metered network while the app is not in front.
 */
data class Pace(
    val interactive: Boolean = true,
    val idle: Boolean = false,
    val powerSave: Boolean = false,
    val metered: Boolean = false,
    val inFront: Boolean = false,
) {
    val saving get() = !interactive || idle || powerSave || metered && !inFront
}

/** Whether mDNS needs every multicast packet the Wi-Fi carries: not while saving, unless a join may meet on the LAN. */
internal fun holdsMulticast(pace: Pace, join: JoinState) = !pace.saving || join is JoinState.Running

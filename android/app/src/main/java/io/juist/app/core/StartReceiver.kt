package io.juist.app.core

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Turns the VPN on again after a reboot or an update of the app, where it was on before. */
class StartReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        Juist.resume(context, afresh = true)
    }
}

package io.juist.app

import android.graphics.Color
import android.content.Intent
import android.os.Bundle
import androidx.compose.runtime.mutableStateOf
import io.juist.app.core.InviteCode
import androidx.activity.SystemBarStyle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import io.juist.app.core.Juist
import io.juist.app.ui.AppRoot
import io.juist.app.ui.theme.JuistTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(navigationBarStyle = SystemBarStyle.auto(Color.TRANSPARENT, Color.TRANSPARENT))
        window.isNavigationBarContrastEnforced = false
        // Only on a fresh start: a recreated activity has handled it already.
        if (savedInstanceState == null) opened.value = inviteLinkOf(intent)
        setContent { JuistTheme { AppRoot(opened) } }
    }

    /** An invite link the activity was opened with, until the app takes it. */
    private val opened = mutableStateOf<String?>(null)

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        inviteLinkOf(intent)?.let { opened.value = it }
    }

    override fun onStart() {
        super.onStart()
        Juist.visible = true
        Juist.refreshSoon()
    }

    override fun onStop() {
        Juist.visible = false
        super.onStop()
    }
}

/** The invite link an intent opens, where it opens one. */
internal fun inviteLinkOf(intent: Intent?): String? =
    intent?.takeIf { it.action == Intent.ACTION_VIEW }?.dataString?.takeIf { InviteCode.isLink(it) }

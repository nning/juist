package io.juist.app

import android.app.Application
import io.juist.app.core.Juist

class JuistApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Juist.init(this)
    }
}

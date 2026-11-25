package io.juist.app

import android.app.ActivityManager
import android.app.Application
import android.app.ApplicationExitInfo
import io.juist.app.core.Juist
import io.juist.app.core.OffReason
import io.juist.app.core.Report
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.shadows.ShadowActivityManager.ApplicationExitInfoBuilder

@RunWith(RobolectricTestRunner::class)
class ReportTest {
    private val app: Application = RuntimeEnvironment.getApplication()

    /** What ended the app's processes and when Android revoked the VPN survive the process, for a lock's report. */
    @Test
    fun theReportSaysHowTheLastProcessesEnded() {
        assertTrue(Report.ends(app).contains("vpn revoked: never"))
        shadowOf(app.getSystemService(ActivityManager::class.java)).addApplicationExitInfo(
            ApplicationExitInfoBuilder.newBuilder()
                .setProcessName(app.packageName)
                .setReason(ApplicationExitInfo.REASON_USER_REQUESTED)
                .setDescription("stop io.juist.debug due to from pid 4242")
                .setTimestamp(1_700_000_000_000)
                .build(),
        )
        Juist.init(app)
        Juist.detached(app, OffReason.Revoked)
        val ends = Report.ends(app)
        assertTrue(ends, Regex("user-requested status=0 importance=\\d+ stop io.juist.debug due to from pid 4242").containsMatchIn(ends))
        assertTrue(ends, !ends.contains("vpn revoked: never"))
        assertTrue(ends, !ends.contains("core failed"))
        Juist.failed(app, "this device's keystore holds no key for juist")
        assertTrue(Report.ends(app).contains("core failed to start"))
    }
}

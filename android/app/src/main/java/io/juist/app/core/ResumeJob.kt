package io.juist.app.core

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import java.util.concurrent.TimeUnit

/** Starts the process now and then while the VPN is wanted, so that one that died turns it on again. */
class ResumeJob : JobService() {
    override fun onStartJob(params: JobParameters?): Boolean {
        Juist.resume(this)
        return false
    }

    override fun onStopJob(params: JobParameters?) = false

    companion object {
        const val ID = 1

        /** Schedules the job where on, unless it is scheduled already, which would reset its period; else cancels it. */
        fun follow(context: Context, on: Boolean) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            if (!on) {
                scheduler.cancel(ID)
            } else if (scheduler.getPendingJob(ID) == null) {
                scheduler.schedule(
                    JobInfo.Builder(ID, ComponentName(context, ResumeJob::class.java))
                        .setPeriodic(TimeUnit.MINUTES.toMillis(15), TimeUnit.MINUTES.toMillis(5))
                        .build(),
                )
            }
        }
    }
}

package io.juist.app.core

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** The core's latest log lines, kept in memory alone, for a person to copy when something goes wrong. */
object Diagnostics {
    private const val MAX_LINES = 400
    private val lines = ArrayDeque<String>()
    private val time = SimpleDateFormat("HH:mm:ss", Locale.ROOT)

    @Synchronized
    fun add(line: String) {
        if (lines.size == MAX_LINES) lines.removeFirst()
        lines.addLast("${time.format(Date())} $line")
    }

    @Synchronized
    fun text(): String = lines.joinToString("\n")
}

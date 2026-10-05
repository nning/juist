package io.juist.app.core

import io.juist.mobile.Mobile

/** What is wrong with a typed invite code, for the screen to say in its own words. */
sealed interface CodeProblem {
    data object Incomplete : CodeProblem
    data object Number : CodeProblem
    data class UnknownWord(val word: String) : CodeProblem
    data class WrongPlace(val word: String) : CodeProblem
}

/** What the core knows of invites, which tests stand in for: its native library loads on a phone alone. */
interface InviteChecks {
    /** The words at word position, from 0 after the number, that start with prefix. */
    fun completions(prefix: String, position: Int): List<String>

    /** What is wrong with a link, in the core's words, or null. */
    fun linkProblem(link: String): String?
}

object CoreInviteChecks : InviteChecks {
    override fun completions(prefix: String, position: Int): List<String> =
        Mobile.completeWord(prefix, position.toLong()).lines().filter { it.isNotEmpty() }

    override fun linkProblem(link: String): String? = Mobile.checkInvite(link).takeIf { it.isNotEmpty() }
}

/**
 * Invite codes as people type them: "42-drumbeat-tolerance-glucose", in any
 * case, with spaces or hyphens. The words alternate between two lists, so a
 * word one place off is told apart from a misspelt one.
 */
object InviteCode {
    const val WORDS = 3
    private const val MAX_NUMBER = 999

    /** Splits typed text into its parts, the number first. */
    fun parts(text: String): List<String> =
        text.trim().lowercase().split(Regex("[\\s-]+")).filter { it.isNotEmpty() }

    /** Rejoins parts as the code is written. */
    fun canonical(parts: List<String>) = parts.joinToString("-")

    fun isLink(text: String) = text.trim().trim('\'', '"').startsWith("juist:")

    /** The words at word position that start with prefix. */
    fun completions(checks: InviteChecks, prefix: String, position: Int): List<String> {
        if (prefix.isEmpty() || position !in 0 until WORDS) return emptyList()
        return checks.completions(prefix, position)
    }

    /** The first problem of a typed code, or null for one that may be redeemed. */
    fun problem(checks: InviteChecks, text: String): CodeProblem? {
        fun known(word: String, position: Int) = word in completions(checks, word, position)
        val parts = parts(text)
        if (parts.isEmpty()) return CodeProblem.Incomplete
        val number = parts[0].toIntOrNull()
        if (number == null || number !in 1..MAX_NUMBER) return CodeProblem.Number
        for ((i, word) in parts.drop(1).take(WORDS).withIndex()) {
            if (!known(word, i)) {
                return if (known(word, i + 1)) CodeProblem.WrongPlace(word) else CodeProblem.UnknownWord(word)
            }
        }
        return if (parts.size == 1 + WORDS) null else CodeProblem.Incomplete
    }
}

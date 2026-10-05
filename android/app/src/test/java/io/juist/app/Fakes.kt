package io.juist.app

import io.juist.app.core.InviteChecks

/** A few words of each of the two lists, in the places codes use them. */
object FakeInviteChecks : InviteChecks {
    private val even = listOf("billiard", "drumbeat", "drifter", "glucose", "adrift")
    private val odd = listOf("tolerance", "virginia", "adroitness", "holiness")

    override fun completions(prefix: String, position: Int): List<String> =
        (if (position % 2 == 0) even else odd).filter { it.startsWith(prefix) }.take(6)

    override fun linkProblem(link: String): String? = if (link.contains('@')) null else "no address"
}

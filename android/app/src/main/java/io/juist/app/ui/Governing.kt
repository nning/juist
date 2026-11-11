package io.juist.app.ui

import android.app.KeyguardManager
import android.content.Context
import io.juist.app.R
import io.juist.app.core.AdminKeys
import io.juist.app.core.AdminSeeds
import io.juist.app.core.Founded
import io.juist.app.core.Juist
import io.juist.app.core.NetworkView
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** Keys need the phone's screen lock, which it has none of. */
class NoScreenLock(cause: Throwable) : Exception(cause)

/**
 * The phone's admin keys in the screens' hands: each use asks the person to
 * authenticate it first, and the seed lives for that one call.
 */
class Governing(private val context: Context) {
    private val keys = AdminKeys(context)

    /** The file name the key pub is kept under. */
    private fun idOf(pub: String) = pub.map { if (it.isLetterOrDigit()) it else '_' }.joinToString("")

    /** The admin key of view's network the phone holds, as the view names it, null for none. */
    fun heldKey(view: NetworkView?): String? = view?.admins?.firstOrNull { keys.has(idOf(it)) }

    /** Whether the phone holds the admin key pub. */
    fun holds(pub: String) = pub.isNotEmpty() && keys.has(idOf(pub))

    /**
     * Creates an admin key behind the person's authentication, and founds
     * network with this phone named name in it: null where they did not
     * authenticate.
     */
    suspend fun create(network: String, name: String): Result<Founded>? {
        val cipher = runCatching { keys.sealing() }.getOrElse {
            val secure = context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true
            return Result.failure(if (secure) it else NoScreenLock(it))
        }
        val authed = authenticate(context, context.getString(R.string.auth_create_title), network, cipher) ?: return null
        // Through to the end once authenticated: a screen recreated meanwhile finds the outcome in Juist.founded.
        return withContext(NonCancellable) {
            val seed = AdminSeeds.new()
            try {
                val pub = AdminSeeds.publicOf(seed)
                val id = idOf(pub)
                // Kept first: a network founded with a key that is not kept has no admin.
                runCatching { keys.keep(id, authed, seed) }.onFailure { return@withContext Result.failure(it) }
                Juist.create(context, network, name, seed)
                    .map { it.copy(admin = pub) }
                    .onSuccess { Juist.founded(it) }
                    .onFailure { keys.forget(id) }
            } finally {
                seed.fill(0)
            }
        }
    }

    /** Runs use with the seed of pub once the person authenticated why; null where they did not. */
    suspend fun <T> withKey(pub: String, why: String, use: suspend (ByteArray) -> Result<T>): Result<T>? {
        val id = idOf(pub)
        val cipher = runCatching { keys.opening(id) }.getOrElse { return Result.failure(it) }
        val authed = authenticate(context, context.getString(R.string.auth_title), why, cipher) ?: return null
        val seed = runCatching { keys.open(id, authed) }.getOrElse { return Result.failure(it) }
        try {
            return use(seed)
        } finally {
            seed.fill(0)
        }
    }
}

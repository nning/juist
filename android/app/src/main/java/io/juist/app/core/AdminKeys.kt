package io.juist.app.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import io.juist.mobile.Mobile
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The admin keys the phone holds, one per network, by the network's id: each
 * a seed sealed under an AES-256-GCM key that Android Keystore holds and uses
 * only right after the user authenticated, by biometric or the device's
 * credential, for that one operation, and never while the phone is locked.
 * The core gets a seed for one call and keeps none.
 */
class AdminKeys(context: Context) {
    private val dir = File(context.noBackupFilesDir, "admin")

    /** Whether the phone holds network's admin key. */
    fun has(network: String): Boolean = file(network).exists()

    /**
     * The cipher that seals a new key, once the user authenticated it. A key
     * Android invalidated, as when the screen lock was removed, is replaced:
     * the admin keys it sealed are lost with it.
     */
    fun sealing(): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key())
        } catch (_: KeyPermanentlyInvalidatedException) {
            keyStore().deleteEntry(ALIAS)
            cipher.init(Cipher.ENCRYPT_MODE, key())
        }
        return cipher
    }

    /** The cipher that opens network's key, once the user authenticated it. */
    fun opening(network: String): Cipher {
        val f = file(network)
        // Gone or damaged, a key file opens never again; other read errors may pass.
        if (!f.exists()) throw AdminKeyLost(GeneralSecurityException("no admin key file"))
        val sealed = f.readBytes()
        if (sealed.size < 1 + IV_BYTES + TAG_BITS / 8 || sealed[0] != VERSION) {
            throw AdminKeyLost(GeneralSecurityException("not sealed by this app"))
        }
        val stored = keyStore().getKey(ALIAS, null) as? SecretKey
            // Android deletes an authenticated key when the screen lock goes.
            ?: throw AdminKeyLost(GeneralSecurityException("this device's keystore holds no admin key for juist"))
        return try {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, stored, GCMParameterSpec(TAG_BITS, sealed, 1, IV_BYTES))
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw AdminKeyLost(e)
        }
    }

    /** Keeps seed as network's key, sealed by cipher, from [sealing] and authenticated. */
    fun keep(network: String, cipher: Cipher, seed: ByteArray) {
        cipher.updateAAD(aad(network))
        val sealed = cipher.doFinal(seed)
        check(cipher.iv.size == IV_BYTES) { "Keystore chose a ${cipher.iv.size}-byte IV" }
        dir.mkdirs()
        val f = AtomicFile(file(network))
        val out = f.startWrite()
        try {
            out.write(byteArrayOf(VERSION) + cipher.iv + sealed)
            f.finishWrite(out)
        } catch (e: Exception) {
            f.failWrite(out)
            throw e
        }
    }

    /** network's key, opened by cipher, from [opening] and authenticated. */
    fun open(network: String, cipher: Cipher): ByteArray {
        val sealed = file(network).readBytes()
        cipher.updateAAD(aad(network))
        return try {
            cipher.doFinal(sealed, 1 + IV_BYTES, sealed.size - 1 - IV_BYTES)
        } catch (e: AEADBadTagException) {
            // Sealed by a Keystore key since replaced, as after the screen lock was removed.
            throw AdminKeyLost(e)
        }
    }

    /** Forgets network's key, where founding it failed; leaving keeps it. */
    fun forget(network: String) {
        file(network).delete()
    }

    private fun file(network: String): File {
        require(network.isNotEmpty() && network.all { it.isLetterOrDigit() || it == '-' || it == '_' }) { "bad network id" }
        return File(dir, "$network.key")
    }

    private fun aad(network: String) = "juist admin key v1 $network".toByteArray()

    private companion object {
        const val ALIAS = "juist-admin-keys"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val VERSION: Byte = 1
        const val IV_BYTES = 12
        const val TAG_BITS = 128

        fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        @Synchronized
        fun key(): SecretKey {
            (keyStore().getKey(ALIAS, null) as? SecretKey)?.let { return it }
            return try {
                generate(strongBox = true)
            } catch (_: StrongBoxUnavailableException) {
                generate(strongBox = false)
            }
        }

        fun generate(strongBox: Boolean): SecretKey {
            val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true)
                // Zero: every use needs an authentication of its own, bound to it.
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .setUnlockedDeviceRequired(true)
                .setInvalidatedByBiometricEnrollment(false)
                .setIsStrongBoxBacked(strongBox)
                .build()
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                init(spec)
                generateKey()
            }
        }
    }
}

/** What the core makes of an admin key's seed, without a network: no core need run. */
object AdminSeeds {
    fun new(): ByteArray = Mobile.newAdminKey()

    /** The public key of seed's admin key, as `juist admins` lists it and a network's view names it. */
    fun publicOf(seed: ByteArray): String = Mobile.adminKeyOf(seed)

    /** seed as the line `juist admins export` prints, for a password manager. */
    fun line(seed: ByteArray): String = Mobile.adminLine(seed)

    /** seed as a line only password opens, which `juist admins import` reads too. */
    fun sealed(seed: ByteArray, password: String): String = Mobile.sealAdminLine(seed, password)
}

/** The Keystore key that sealed the phone's admin keys is gone, as when the screen lock was removed. */
class AdminKeyLost(cause: Throwable) : GeneralSecurityException(cause)

package com.openwearsync.wear

import android.content.Context
import android.content.SharedPreferences
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

// START_MODULE_CONTRACT
// PURPOSE: Persistent Android Keystore-encrypted store for paired Windows receiver credentials and server fingerprint.
// SCOPE: AndroidKeyStore AES/GCM encryption of device ID, shared secret hex, pinned server fingerprint, and receiver endpoint across app restarts.
// DEPENDS: M-WEAR-SHELL, M-PAIRING-SECURITY
// LINKS: M-WEAR-SHELL, M-PAIRING-SECURITY, V-M-PAIRING-SECURITY, DF-DISCOVERY-AND-PAIRING
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   PeerCredentials - data model holding enrolled pairing credentials and pinned server identity.
//   PeerCredentialsStore - AndroidKeyStore-backed secure storage persisting pairing credentials.
// END_MODULE_MAP

data class PeerCredentials(
    val deviceId: String,
    val sharedSecretHex: String,
    val serverFingerprint: String,
    val receiverHost: String,
    val receiverPort: Int,
)

class PeerCredentialsStore private constructor(
    private val preferences: () -> SharedPreferences,
    private val keyProvider: (() -> SecretKey)?,
) {
    constructor(context: Context) : this({ context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) }, null)
    internal constructor(prefs: SharedPreferences, keyProvider: () -> SecretKey) : this({ prefs }, keyProvider)
    @Volatile private var storageFailed = false
    private val prefs: SharedPreferences by lazy {
        preferences()
    }

    companion object {
        private const val PREFS_NAME = "openwearsync_credentials"
        private const val KEYSTORE_ALIAS = "openwearsync_master_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_GCM_NO_PADDING = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12

        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_SHARED_SECRET_ENC = "shared_secret_enc"
        private const val KEY_SERVER_FINGERPRINT_ENC = "server_fingerprint_enc"
        private const val KEY_RECEIVER_HOST = "receiver_host"
        private const val KEY_RECEIVER_PORT = "receiver_port"
        private const val KEY_VERSION = "credential_version"
        private const val VERSION = 2

        private fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        private fun hexToBytes(s: String): ByteArray {
            val trimmed = s.trim()
            require(trimmed.length % 2 == 0 && trimmed.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
            val data = ByteArray(trimmed.length / 2)
            for (i in 0 until trimmed.length step 2) {
                data[i / 2] = ((Character.digit(trimmed[i], 16) shl 4) + Character.digit(trimmed[i + 1], 16)).toByte()
            }
            return data
        }
    }

    private fun getSecretKey(): SecretKey {
            keyProvider?.let { return it() }
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
                val keyGen = KeyGenerator.getInstance("AES", ANDROID_KEYSTORE)
                val spec = android.security.keystore.KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or
                            android.security.keystore.KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                keyGen.init(spec)
                keyGen.generateKey()
            }
            return (keyStore.getEntry(KEYSTORE_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private fun encryptString(plaintext: String): String? {
        return try {
            val secretKey = getSecretKey()
            val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val iv = requireNotNull(cipher.iv)
            require(iv.size == GCM_IV_LENGTH)
            val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            val combined = ByteArray(iv.size + ciphertext.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(ciphertext, 0, combined, iv.size, ciphertext.size)
            bytesToHex(combined)
        } catch (_: Throwable) {
            null
        }
    }

    private fun decryptString(hex: String): String? {
        return try {
            val combined = hexToBytes(hex)
            if (combined.size <= GCM_IV_LENGTH) return null
            val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
            val ciphertext = combined.copyOfRange(GCM_IV_LENGTH, combined.size)
            val secretKey = getSecretKey()
            val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            val decryptedBytes = cipher.doFinal(ciphertext)
            String(decryptedBytes, Charsets.UTF_8)
        } catch (_: Throwable) {
            null
        }
    }

    fun isPaired(): Boolean {
        return getCredentials() != null
    }

    fun getCredentials(): PeerCredentials? {
        if (storageFailed || prefs.getInt(KEY_VERSION, 0) != VERSION) return null
        val deviceId = prefs.getString(KEY_DEVICE_ID, null) ?: return null
        val encSecret = prefs.getString(KEY_SHARED_SECRET_ENC, null) ?: return null
        val secret = decryptString(encSecret) ?: return null
        val encFp = prefs.getString(KEY_SERVER_FINGERPRINT_ENC, null) ?: return null
        val fingerprint = decryptString(encFp) ?: return null
        if (!secret.matches(Regex("[0-9a-fA-F]{64}")) || !fingerprint.matches(Regex("[0-9a-fA-F]{64}"))) return null
        val host = prefs.getString(KEY_RECEIVER_HOST, "192.168.1.100") ?: "192.168.1.100"
        val port = prefs.getInt(KEY_RECEIVER_PORT, 35659)
        return PeerCredentials(
            deviceId = deviceId,
            sharedSecretHex = secret,
            serverFingerprint = fingerprint,
            receiverHost = host,
            receiverPort = port,
        )
    }

    fun savePairing(
        deviceId: String,
        sharedSecretHex: String,
        serverFingerprint: String,
        host: String,
        port: Int,
    ): Boolean {
        if (!sharedSecretHex.matches(Regex("[0-9a-fA-F]{64}")) || !serverFingerprint.matches(Regex("[0-9a-fA-F]{64}"))) return false
        val encSecret = encryptString(sharedSecretHex) ?: return false
        val encFp = encryptString(serverFingerprint) ?: return false
        // Android updates its shared in-memory preferences even when durable commit fails.
        // Restore this store's previous fields so a newly created store cannot accept the failed save.
        val previousStrings = try { listOf(KEY_DEVICE_ID, KEY_SHARED_SECRET_ENC, KEY_SERVER_FINGERPRINT_ENC, KEY_RECEIVER_HOST)
            .associateWith { prefs.getString(it, null) } } catch (_: Exception) { return false }
        val previousVersion = prefs.getInt(KEY_VERSION, 0)
        val previousPort = prefs.getInt(KEY_RECEIVER_PORT, 0)
        val saved = try { prefs.edit()
            .putInt(KEY_VERSION, VERSION)
            .putString(KEY_DEVICE_ID, deviceId)
            .putString(KEY_SHARED_SECRET_ENC, encSecret)
            .putString(KEY_SERVER_FINGERPRINT_ENC, encFp)
            .putString(KEY_RECEIVER_HOST, host)
            .putInt(KEY_RECEIVER_PORT, port)
            .commit() } catch (_: Exception) { false }
        storageFailed = !saved
        if (!saved) {
            try {
                val restore = prefs.edit().putInt(KEY_VERSION, previousVersion).putInt(KEY_RECEIVER_PORT, previousPort)
                previousStrings.forEach { (key, value) -> restore.putString(key, value) }
                restore.commit()
            } catch (_: Exception) { /* The current instance remains closed after storage failure. */ }
        }
        return saved
    }

    fun clearPairing() {
        prefs.edit().clear().apply()
        storageFailed = false
    }
}

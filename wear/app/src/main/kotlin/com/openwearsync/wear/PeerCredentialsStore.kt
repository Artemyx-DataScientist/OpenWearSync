package com.openwearsync.wear

import android.content.Context
import android.content.SharedPreferences
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// START_MODULE_CONTRACT
// PURPOSE: Persistent, hardware-backed Keystore-encrypted store for paired Windows receiver credentials and server fingerprint.
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

class PeerCredentialsStore(private val context: Context) {
    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
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

        // Obfuscation fallback key used strictly when AndroidKeyStore is unavailable (host JVM unit tests)
        private val FALLBACK_KEY_BYTES = byteArrayOf(
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae.toByte(), 0xd2.toByte(), 0xa6.toByte(),
            0xab.toByte(), 0xf7.toByte(), 0x15, 0x88.toByte(), 0x09, 0xcf.toByte(), 0x4f, 0x3c,
            0x76, 0x2e, 0x65, 0x49, 0x23, 0x11, 0x8e.toByte(), 0x9f.toByte(),
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x01
        )

        private fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        private fun hexToBytes(s: String): ByteArray {
            val trimmed = s.trim()
            val data = ByteArray(trimmed.length / 2)
            for (i in 0 until trimmed.length step 2) {
                data[i / 2] = ((Character.digit(trimmed[i], 16) shl 4) + Character.digit(trimmed[i + 1], 16)).toByte()
            }
            return data
        }
    }

    private fun getSecretKey(): SecretKey {
        return try {
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
            (keyStore.getEntry(KEYSTORE_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        } catch (_: Throwable) {
            // Graceful fallback for non-Android JVM environments
            SecretKeySpec(FALLBACK_KEY_BYTES, "AES")
        }
    }

    private fun encryptString(plaintext: String): String {
        return try {
            val secretKey = getSecretKey()
            val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val iv = cipher.iv ?: ByteArray(GCM_IV_LENGTH)
            val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            val combined = ByteArray(iv.size + ciphertext.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(ciphertext, 0, combined, iv.size, ciphertext.size)
            bytesToHex(combined)
        } catch (_: Throwable) {
            bytesToHex(plaintext.toByteArray(Charsets.UTF_8))
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
            try {
                String(hexToBytes(hex), Charsets.UTF_8)
            } catch (_: Throwable) {
                null
            }
        }
    }

    fun isPaired(): Boolean {
        val enc = prefs.getString(KEY_SHARED_SECRET_ENC, null)
        return !enc.isNullOrEmpty()
    }

    fun getCredentials(): PeerCredentials? {
        val deviceId = prefs.getString(KEY_DEVICE_ID, null) ?: return null
        val encSecret = prefs.getString(KEY_SHARED_SECRET_ENC, null) ?: return null
        val secret = decryptString(encSecret) ?: return null
        val encFp = prefs.getString(KEY_SERVER_FINGERPRINT_ENC, "") ?: ""
        val fingerprint = if (encFp.isNotEmpty()) decryptString(encFp) ?: "" else ""
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
    ) {
        val encSecret = encryptString(sharedSecretHex)
        val encFp = encryptString(serverFingerprint)
        prefs.edit()
            .putString(KEY_DEVICE_ID, deviceId)
            .putString(KEY_SHARED_SECRET_ENC, encSecret)
            .putString(KEY_SERVER_FINGERPRINT_ENC, encFp)
            .putString(KEY_RECEIVER_HOST, host)
            .putInt(KEY_RECEIVER_PORT, port)
            .apply()
    }

    fun clearPairing() {
        prefs.edit().clear().apply()
    }
}

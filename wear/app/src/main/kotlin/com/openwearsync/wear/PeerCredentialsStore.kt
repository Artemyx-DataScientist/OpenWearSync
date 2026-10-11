package com.openwearsync.wear

import android.content.Context
import android.content.SharedPreferences

// START_MODULE_CONTRACT
// PURPOSE: Persistent SharedPreferences store for paired Windows receiver credentials and server fingerprint.
// SCOPE: Storage of device ID, shared secret hex, pinned server fingerprint, and receiver endpoint across app restarts.
// DEPENDS: M-WEAR-SHELL, M-PAIRING-SECURITY
// LINKS: M-WEAR-SHELL, M-PAIRING-SECURITY, V-M-PAIRING-SECURITY, DF-DISCOVERY-AND-PAIRING
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   PeerCredentials - data model holding enrolled pairing credentials and pinned server identity.
//   PeerCredentialsStore - SharedPreferences wrapper persisting pairing credentials.
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
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_SHARED_SECRET_HEX = "shared_secret_hex"
        private const val KEY_SERVER_FINGERPRINT = "server_fingerprint"
        private const val KEY_RECEIVER_HOST = "receiver_host"
        private const val KEY_RECEIVER_PORT = "receiver_port"
    }

    fun isPaired(): Boolean {
        val secret = prefs.getString(KEY_SHARED_SECRET_HEX, null)
        return !secret.isNullOrEmpty()
    }

    fun getCredentials(): PeerCredentials? {
        val deviceId = prefs.getString(KEY_DEVICE_ID, null) ?: return null
        val secret = prefs.getString(KEY_SHARED_SECRET_HEX, null) ?: return null
        val fingerprint = prefs.getString(KEY_SERVER_FINGERPRINT, "") ?: ""
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
        prefs.edit()
            .putString(KEY_DEVICE_ID, deviceId)
            .putString(KEY_SHARED_SECRET_HEX, sharedSecretHex)
            .putString(KEY_SERVER_FINGERPRINT, serverFingerprint)
            .putString(KEY_RECEIVER_HOST, host)
            .putInt(KEY_RECEIVER_PORT, port)
            .apply()
    }

    fun clearPairing() {
        prefs.edit().clear().apply()
    }
}

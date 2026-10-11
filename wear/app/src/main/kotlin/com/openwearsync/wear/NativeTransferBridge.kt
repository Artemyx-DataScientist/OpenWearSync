package com.openwearsync.wear

import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// START_MODULE_CONTRACT
// PURPOSE: Kotlin JNI bridge loading libopenwearsync_android_ffi.so and wrapping native Rust transfer engine.
// SCOPE: Native lifecycle handles, reconciliation, cancellation signals, SHA-256, PAKE derivation, and native socket chunk upload.
// DEPENDS: M-ANDROID-PLATFORM, M-TRANSFER-CORE, M-PAIRING-SECURITY
// LINKS: M-ANDROID-PLATFORM, M-TRANSFER-CORE, DF-ENCRYPTED-CHUNK-UPLOAD, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   PakeKeysResult - container for client proof, server proof, and derived shared secret.
//   NativeTransferBridge - JNI wrapper object providing native session operations, native socket I/O, and JVM fallback implementations.
// END_MODULE_MAP

data class PakeKeysResult(
    val clientProofHex: String,
    val serverProofHex: String,
    val sharedSecretHex: String,
)

object NativeTransferBridge {
    val isNativeLoaded: Boolean

    init {
        var loaded = false
        try {
            System.loadLibrary("openwearsync_android_ffi")
            loaded = true
        } catch (_: Throwable) {
            loaded = false
        }
        isNativeLoaded = loaded
    }

    // Native C-JNI entry points (exported from crates/android-ffi)
    @JvmStatic
    external fun nativeCreateSession(totalBytes: Long): Long

    @JvmStatic
    external fun nativeCancelSession(handle: Long): Int

    @JvmStatic
    external fun nativePauseSession(handle: Long): Int

    @JvmStatic
    external fun nativeResumeSession(handle: Long): Int

    @JvmStatic
    external fun nativeGetStatus(handle: Long): Int

    @JvmStatic
    external fun nativeGetProgress(handle: Long): Long

    @JvmStatic
    external fun nativeRecordChunk(handle: Long, offset: Long, length: Int): Int

    @JvmStatic
    external fun nativeIsChunkReceived(handle: Long, offset: Long, length: Int): Int

    @JvmStatic
    external fun nativeDestroySession(handle: Long): Int

    @JvmStatic
    external fun nativeCreateTransferSocket(
        host: String,
        port: Int,
        manifestJson: String,
        token: String,
    ): String?

    @JvmStatic
    external fun nativeUploadChunkSocket(
        host: String,
        port: Int,
        transferId: String,
        offset: Long,
        chunkData: ByteArray,
        token: String,
        isEncrypted: Byte,
    ): Int

    @JvmStatic
    external fun nativeReconcileSocket(
        host: String,
        port: Int,
        transferId: String,
        token: String,
    ): String?

    @JvmStatic
    external fun nativeCommitSocket(
        host: String,
        port: Int,
        transferId: String,
        token: String,
    ): String?

    @JvmStatic
    external fun nativeDerivePakeKeys(
        pin: String,
        saltHex: String,
        serverNonceHex: String,
        clientNonceHex: String,
        deviceId: String,
        serverFingerprint: String,
    ): String?

    @JvmStatic
    external fun nativeEncryptChunk(
        keyBytes: ByteArray,
        offset: Long,
        payloadBytes: ByteArray,
    ): ByteArray?

    @JvmStatic
    external fun nativeComputeSha256(
        dataBytes: ByteArray,
    ): ByteArray

    // Safe wrappers that gracefully work whether running on Android ARM64 device or JVM host test
    fun createSession(totalBytes: Long): Long {
        return if (isNativeLoaded) {
            try { nativeCreateSession(totalBytes) } catch (_: Throwable) { 0L }
        } else {
            0L
        }
    }

    fun cancelSession(handle: Long) {
        if (isNativeLoaded && handle != 0L) {
            try { nativeCancelSession(handle) } catch (_: Throwable) {}
        }
    }

    fun pauseSession(handle: Long) {
        if (isNativeLoaded && handle != 0L) {
            try { nativePauseSession(handle) } catch (_: Throwable) {}
        }
    }

    fun resumeSession(handle: Long) {
        if (isNativeLoaded && handle != 0L) {
            try { nativeResumeSession(handle) } catch (_: Throwable) {}
        }
    }

    fun getProgress(handle: Long): Long {
        return if (isNativeLoaded && handle != 0L) {
            try { nativeGetProgress(handle) } catch (_: Throwable) { 0L }
        } else {
            0L
        }
    }

    fun recordChunk(handle: Long, offset: Long, length: Int) {
        if (isNativeLoaded && handle != 0L) {
            try { nativeRecordChunk(handle, offset, length) } catch (_: Throwable) {}
        }
    }

    fun isChunkReceived(handle: Long, offset: Long, length: Int): Boolean {
        return if (isNativeLoaded && handle != 0L) {
            try { nativeIsChunkReceived(handle, offset, length) == 1 } catch (_: Throwable) { false }
        } else {
            false
        }
    }

    fun destroySession(handle: Long) {
        if (isNativeLoaded && handle != 0L) {
            try { nativeDestroySession(handle) } catch (_: Throwable) {}
        }
    }

    fun deriveSharedSecret(pin: String, deviceId: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(pin.trim().toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(deviceId.trim().toByteArray(Charsets.UTF_8))
    }

    fun computeSha256(data: ByteArray): ByteArray {
        if (isNativeLoaded) {
            try {
                return nativeComputeSha256(data)
            } catch (_: Throwable) {}
        }
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    // PAKE key derivation with native acceleration and pure Kotlin fallback
    fun derivePakeKeys(
        pin: String,
        saltHex: String,
        serverNonceHex: String,
        clientNonceHex: String,
        deviceId: String,
        serverFingerprint: String,
    ): PakeKeysResult {
        if (isNativeLoaded) {
            try {
                val json = nativeDerivePakeKeys(
                    pin,
                    saltHex,
                    serverNonceHex,
                    clientNonceHex,
                    deviceId,
                    serverFingerprint,
                )
                if (json != null) {
                    val cp = extractJson(json, "client_proof_hex")
                    val sp = extractJson(json, "server_proof_hex")
                    val sec = extractJson(json, "shared_secret_hex")
                    if (cp != null && sp != null && sec != null) {
                        return PakeKeysResult(cp, sp, sec)
                    }
                }
            } catch (_: Throwable) {}
        }

        // JVM Fallback: identical to crates/security/src/lib.rs derive_pake_keys
        val salt = hexToBytes(saltHex)
        val serverNonce = hexToBytes(serverNonceHex)
        val clientNonce = hexToBytes(clientNonceHex)

        // 5000 rounds of HMAC-SHA256
        var stretched = hmacSha256(pin.toByteArray(Charsets.UTF_8), salt)
        for (i in 1 until 5000) {
            stretched = hmacSha256(pin.toByteArray(Charsets.UTF_8), stretched)
        }

        val authInput = "OpenWearSync-PAKE-Auth-v1".toByteArray(Charsets.UTF_8) +
                serverNonce + clientNonce + deviceId.toByteArray(Charsets.UTF_8)
        val kAuth = hmacSha256(stretched, authInput)

        val masterInput = "OpenWearSync-PAKE-Master-v1".toByteArray(Charsets.UTF_8) +
                serverFingerprint.toByteArray(Charsets.UTF_8)
        val sharedSecret = hmacSha256(kAuth, masterInput)

        val cpInput = "OpenWearSync-ClientProof-v1".toByteArray(Charsets.UTF_8) +
                clientNonce + serverNonce
        val clientProof = hmacSha256(sharedSecret, cpInput)

        val spInput = "OpenWearSync-ServerProof-v1".toByteArray(Charsets.UTF_8) +
                serverNonce + clientNonce
        val serverProof = hmacSha256(sharedSecret, spInput)

        return PakeKeysResult(
            clientProofHex = bytesToHex(clientProof),
            serverProofHex = bytesToHex(serverProof),
            sharedSecretHex = bytesToHex(sharedSecret),
        )
    }

    // Authenticated chunk encryption with native acceleration and pure Kotlin fallback
    fun encryptChunk(
        keyBytes: ByteArray,
        offset: Long,
        payloadBytes: ByteArray,
    ): ByteArray {
        if (isNativeLoaded) {
            try {
                val enc = nativeEncryptChunk(keyBytes, offset, payloadBytes)
                if (enc != null) return enc
            } catch (_: Throwable) {}
        }

        // JVM Fallback: identical to crates/security encrypt_chunk_payload
        val chunkIdx = (offset / 65536L).toInt()
        val nonce = ByteArray(16) { 0 }
        // info: nonce (16) + chunk_idx (4, BE) + block_idx (4, BE)
        val ciphertext = ByteArray(payloadBytes.size)
        var blockIdx = 0
        var keystreamBlock = ByteArray(32)

        for (i in payloadBytes.indices) {
            if (i % 32 == 0) {
                val info = ByteArray(24)
                System.arraycopy(nonce, 0, info, 0, 16)
                info[16] = ((chunkIdx ushr 24) and 0xFF).toByte()
                info[17] = ((chunkIdx ushr 16) and 0xFF).toByte()
                info[18] = ((chunkIdx ushr 8) and 0xFF).toByte()
                info[19] = (chunkIdx and 0xFF).toByte()
                info[20] = ((blockIdx ushr 24) and 0xFF).toByte()
                info[21] = ((blockIdx ushr 16) and 0xFF).toByte()
                info[22] = ((blockIdx ushr 8) and 0xFF).toByte()
                info[23] = (blockIdx and 0xFF).toByte()
                keystreamBlock = hmacSha256(keyBytes, info)
                blockIdx++
            }
            ciphertext[i] = (payloadBytes[i].toInt() xor keystreamBlock[i % 32].toInt()).toByte()
        }

        // Tag: hmac_sha256(key, "OpenWearSync-Payload-Tag-v1" + nonce + chunkIdx (4) + ciphertext)
        val chunkIdxBytes = ByteArray(4).apply {
            this[0] = ((chunkIdx ushr 24) and 0xFF).toByte()
            this[1] = ((chunkIdx ushr 16) and 0xFF).toByte()
            this[2] = ((chunkIdx ushr 8) and 0xFF).toByte()
            this[3] = (chunkIdx and 0xFF).toByte()
        }
        val tagInput = "OpenWearSync-Payload-Tag-v1".toByteArray(Charsets.UTF_8) +
                nonce + chunkIdxBytes + ciphertext
        val tag = hmacSha256(keyBytes, tagInput)

        val out = ByteArray(16 + ciphertext.size + 32)
        System.arraycopy(nonce, 0, out, 0, 16)
        System.arraycopy(ciphertext, 0, out, 16, ciphertext.size)
        System.arraycopy(tag, 0, out, 16 + ciphertext.size, 32)
        return out
    }

    // Socket HTTP request via native Rust or standard JVM HttpURLConnection
    fun createTransferSocket(
        host: String,
        port: Int,
        manifestJson: String,
        token: String,
    ): Pair<Int, String?> {
        if (isNativeLoaded) {
            try {
                val resp = nativeCreateTransferSocket(host, port, manifestJson, token)
                if (resp != null) {
                    val code = extractJsonInt(resp, "status_code") ?: 200
                    return Pair(code, resp)
                }
            } catch (_: Throwable) {}
        }
        return try {
            val url = URL("http://$host:$port/v1/transfers")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 10_000
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Connection", "close")
                if (token.isNotEmpty()) setRequestProperty("Authorization", token)
            }
            conn.outputStream.use { it.write(manifestJson.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val body = if (code in 200..299) conn.inputStream.bufferedReader().use { it.readText() }
            else conn.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
            Pair(code, body)
        } catch (e: Exception) {
            Pair(0, e.message)
        }
    }

    fun uploadChunkSocket(
        host: String,
        port: Int,
        transferId: String,
        offset: Long,
        chunkData: ByteArray,
        token: String,
        isEncrypted: Boolean,
        sha256Hex: String,
    ): Int {
        if (isNativeLoaded) {
            try {
                val code = nativeUploadChunkSocket(
                    host,
                    port,
                    transferId,
                    offset,
                    chunkData,
                    token,
                    if (isEncrypted) 1 else 0,
                )
                if (code > 0) return code
            } catch (_: Throwable) {}
        }
        return try {
            val url = URL("http://$host:$port/v1/transfers/$transferId/chunks/$offset")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "PUT"
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 15_000
                setRequestProperty("Content-Type", "application/octet-stream")
                setRequestProperty("Connection", "close")
                setRequestProperty("x-chunk-sha256", sha256Hex)
                if (isEncrypted) setRequestProperty("x-encrypted", "true")
                if (token.isNotEmpty()) setRequestProperty("Authorization", token)
            }
            conn.outputStream.use { it.write(chunkData) }
            conn.responseCode
        } catch (_: Exception) {
            0
        }
    }

    fun reconcileSocket(
        host: String,
        port: Int,
        transferId: String,
        token: String,
    ): Pair<Int, String?> {
        if (isNativeLoaded) {
            try {
                val resp = nativeReconcileSocket(host, port, transferId, token)
                if (resp != null) {
                    val code = extractJsonInt(resp, "status_code") ?: 200
                    return Pair(code, resp)
                }
            } catch (_: Throwable) {}
        }
        return try {
            val url = URL("http://$host:$port/v1/transfers/$transferId/reconcile")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 8_000
                readTimeout = 8_000
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Connection", "close")
                if (token.isNotEmpty()) setRequestProperty("Authorization", token)
            }
            conn.outputStream.use { it.write("{}".toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val body = if (code in 200..299) conn.inputStream.bufferedReader().use { it.readText() }
            else conn.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
            Pair(code, body)
        } catch (e: Exception) {
            Pair(0, e.message)
        }
    }

    fun commitSocket(
        host: String,
        port: Int,
        transferId: String,
        token: String,
    ): Pair<Int, String?> {
        if (isNativeLoaded) {
            try {
                val resp = nativeCommitSocket(host, port, transferId, token)
                if (resp != null) {
                    val code = extractJsonInt(resp, "status_code") ?: 200
                    return Pair(code, resp)
                }
            } catch (_: Throwable) {}
        }
        return try {
            val url = URL("http://$host:$port/v1/transfers/$transferId/commit")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 10_000
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Connection", "close")
                if (token.isNotEmpty()) setRequestProperty("Authorization", token)
            }
            conn.outputStream.use { it.write("{}".toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val body = if (code in 200..299) conn.inputStream.bufferedReader().use { it.readText() }
            else conn.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
            Pair(code, body)
        } catch (e: Exception) {
            Pair(0, e.message)
        }
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun hexToBytes(s: String): ByteArray {
        val trimmed = s.trim()
        val data = ByteArray(trimmed.length / 2)
        for (i in 0 until trimmed.length step 2) {
            data[i / 2] = ((Character.digit(trimmed[i], 16) shl 4) + Character.digit(trimmed[i + 1], 16)).toByte()
        }
        return data
    }

    private fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun extractJson(json: String, key: String): String? {
        val regex = """"$key"\s*:\s*"([^"]+)"""".toRegex()
        return regex.find(json)?.groupValues?.get(1)
    }

    private fun extractJsonInt(json: String, key: String): Int? {
        val regex = """"$key"\s*:\s*(\d+)""".toRegex()
        return regex.find(json)?.groupValues?.get(1)?.toIntOrNull()
    }
}

package com.openwearsync.wear

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// START_MODULE_CONTRACT
// PURPOSE: Kotlin JNI bridge loading libopenwearsync_android_ffi.so and wrapping native Rust transfer engine.
// SCOPE: Native lifecycle handles, reconciliation, cancellation signals, SHA-256, standard AES-GCM, and independently pinned HTTPS.
// DEPENDS: M-ANDROID-PLATFORM, M-TRANSFER-CORE, M-PAIRING-SECURITY
// LINKS: M-ANDROID-PLATFORM, M-TRANSFER-CORE, DF-ENCRYPTED-CHUNK-UPLOAD, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   NativeTransferBridge - JNI wrapper object providing native session operations, pinned TLS I/O, and standard JVM hash/cipher implementations.
// END_MODULE_MAP

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
    external fun nativeHttpsRequest(host: String, port: Int, pin: String, method: String, path: String,
        token: String, sha256Hex: String, encrypted: Int, body: ByteArray): String?

    @JvmStatic
    external fun nativeEncryptChunk(
        secret: ByteArray,
        nonce: ByteArray,
        chunkIndex: Int,
        plaintext: ByteArray,
        outEncrypted: ByteArray,
    ): Int

    @JvmStatic
    external fun nativeComputeSha256(
        data: ByteArray,
        outSha: ByteArray,
    ): Int

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

    fun getStatus(handle: Long): Int {
        return if (isNativeLoaded && handle != 0L) {
            try { nativeGetStatus(handle) } catch (_: Throwable) { -1 }
        } else {
            -1
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

    fun computeSha256(data: ByteArray): ByteArray {
        if (isNativeLoaded) {
            try {
                val out = ByteArray(32)
                if (nativeComputeSha256(data, out) == 0) {
                    return out
                }
            } catch (_: Throwable) {}
        }
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    fun encryptChunk(keyBytes: ByteArray, nonce: ByteArray, chunkIndex: Int, payloadBytes: ByteArray): ByteArray {
        require(keyBytes.size == 32 && nonce.size == 16 && payloadBytes.size <= 65536)
        if (isNativeLoaded) {
            val out = ByteArray(payloadBytes.size + 16)
            val len = nativeEncryptChunk(keyBytes, nonce, chunkIndex, payloadBytes, out)
            check(len == out.size) { "Native AES-GCM encryption failed" }
            return out
        }
        // RFC 5869 HKDF-SHA256, one 32-byte expand block; Java supplies the AES-GCM primitive.
        fun hmac(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }
        val key = hmac(hmac(nonce, keyBytes), "OpenWearSync/chunk/key/v2".toByteArray(Charsets.UTF_8) + byteArrayOf(1))
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), javax.crypto.spec.GCMParameterSpec(128, ByteArray(12)))
        cipher.updateAAD(ByteArray(4) { (chunkIndex ushr (it * 8)).toByte() })
        return cipher.doFinal(payloadBytes)
    }

    fun httpsRequest(host: String, port: Int, pin: String, method: String, path: String,
        token: String = "", sha256Hex: String = "", encrypted: Boolean = false,
        body: ByteArray = ByteArray(0)): Pair<Int, String?> {
        if (!isNativeLoaded) return Pair(0, "Native TLS library unavailable")
        return try {
            val response = nativeHttpsRequest(host, port, pin, method, path, token, sha256Hex, if (encrypted) 1 else 0, body)
                ?: return Pair(0, "Native TLS returned no response")
            val split = response.indexOf('\n')
            if (split < 0) Pair(0, "Invalid native response")
            else Pair(response.substring(0, split).toIntOrNull() ?: 0, response.substring(split + 1))
        } catch (e: Exception) { Pair(0, e.message) }
          catch (e: LinkageError) { Pair(0, "Native TLS ABI unavailable") }
    }
    fun createTransferSocket(host: String, port: Int, manifestJson: String, token: String, pinnedFingerprint: String) =
        httpsRequest(host, port, pinnedFingerprint, "POST", "/v1/transfers", token, body = manifestJson.toByteArray(Charsets.UTF_8))
    fun uploadChunkSocket(handle: Long, host: String, port: Int, transferId: String, offset: Long,
        chunkData: ByteArray, token: String, isEncrypted: Boolean, sha256Hex: String,
        plaintextLength: Int, pinnedFingerprint: String): Int {
        require(plaintextLength in 1..65536)
        val code = httpsRequest(host, port, pinnedFingerprint, "PUT", "/v1/transfers/$transferId/chunks/$offset",
            token, sha256Hex, isEncrypted, chunkData).first
        if (code == 200) recordChunk(handle, offset, plaintextLength)
        return code
    }
    fun reconcileSocket(handle: Long, host: String, port: Int, transferId: String, token: String, pinnedFingerprint: String) =
        httpsRequest(host, port, pinnedFingerprint, "POST", "/v1/transfers/$transferId/reconcile", token, body = "{}".toByteArray())
    fun commitSocket(host: String, port: Int, transferId: String, token: String, pinnedFingerprint: String) =
        httpsRequest(host, port, pinnedFingerprint, "POST", "/v1/transfers/$transferId/commit", token, body = "{}".toByteArray())
}

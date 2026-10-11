package com.openwearsync.wear

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// START_MODULE_CONTRACT
// PURPOSE: Kotlin JNI bridge loading libopenwearsync_android_ffi.so and wrapping native Rust transfer engine.
// SCOPE: Native lifecycle handles, reconciliation, cancellation signals, SHA-256 and HMAC-SHA256 calculations.
// DEPENDS: M-ANDROID-PLATFORM, M-TRANSFER-CORE, M-PAIRING-SECURITY
// LINKS: M-ANDROID-PLATFORM, M-TRANSFER-CORE, DF-ENCRYPTED-CHUNK-UPLOAD, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   NativeTransferBridge - JNI wrapper object providing native session operations and fallback implementations.
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
        return MessageDigest.getInstance("SHA-256").digest(data)
    }
}

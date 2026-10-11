package com.openwearsync.wear

import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// START_MODULE_CONTRACT
// PURPOSE: Kotlin JNI bridge loading libopenwearsync_android_ffi.so and wrapping native Rust transfer engine.
// SCOPE: Native lifecycle handles, reconciliation, cancellation signals, SHA-256, PAKE derivation, and native socket chunk upload.
// DEPENDS: M-ANDROID-PLATFORM, M-TRANSFER-CORE, M-PAIRING-SECURITY
// LINKS: M-ANDROID-PLATFORM, M-TRANSFER-CORE, DF-ENCRYPTED-CHUNK-UPLOAD, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   PakeKeysResult - container for client proof, server proof, derived shared secret, and client masked public key.
//   NativeTransferBridge - JNI wrapper object providing native session operations, native socket I/O, and JVM fallback implementations.
// END_MODULE_MAP

data class PakeKeysResult(
    val clientProofHex: String,
    val serverProofHex: String,
    val sharedSecretHex: String,
    val clientMaskedPkHex: String = "",
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
        authHeader: String,
    ): Int

    @JvmStatic
    external fun nativeUploadChunkSocket(
        handle: Long,
        host: String,
        port: Int,
        transferId: String,
        offset: Long,
        chunkData: ByteArray,
        isEncrypted: Int,
        authHeader: String,
    ): Int

    @JvmStatic
    external fun nativeReconcileSocket(
        handle: Long,
        host: String,
        port: Int,
        transferId: String,
        authHeader: String,
    ): Int

    @JvmStatic
    external fun nativeCommitSocket(
        host: String,
        port: Int,
        transferId: String,
        authHeader: String,
    ): Int

    @JvmStatic
    external fun nativeDerivePakeKeys(
        pin: String,
        saltHex: String,
        serverNonceHex: String,
        clientNonceHex: String,
        deviceId: String,
        serverFingerprint: String,
        outClientProof: ByteArray,
        outServerProof: ByteArray,
        outSharedSecret: ByteArray,
    ): Int

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

    fun deriveSharedSecret(pin: String, deviceId: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(pin.trim().toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(deviceId.trim().toByteArray(Charsets.UTF_8))
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

    // PAKE key derivation with native acceleration and pure Kotlin RFC 7748 X25519 fallback
    fun derivePakeKeys(
        pin: String,
        saltHex: String,
        serverNonceHex: String,
        clientNonceHex: String,
        deviceId: String,
        serverFingerprint: String,
        serverMaskedPkHex: String? = null,
    ): PakeKeysResult {
        if (isNativeLoaded) {
            try {
                val cp = ByteArray(32)
                val sp = ByteArray(32)
                val sec = ByteArray(32)
                val res = nativeDerivePakeKeys(
                    pin,
                    saltHex,
                    serverNonceHex,
                    clientNonceHex,
                    deviceId,
                    serverFingerprint,
                    cp,
                    sp,
                    sec,
                )
                if (res == 0) {
                    val clientMaskedPk = deriveClientMaskedPk(pin, saltHex, clientNonceHex, serverNonceHex, deviceId)
                    return PakeKeysResult(
                        clientProofHex = bytesToHex(cp),
                        serverProofHex = bytesToHex(sp),
                        sharedSecretHex = bytesToHex(sec),
                        clientMaskedPkHex = clientMaskedPk,
                    )
                }
            } catch (_: Throwable) {}
        }

        // JVM Fallback: identical to crates/security/src/lib.rs derive_pake_keys / X25519-EKE
        val salt = hexToBytes(saltHex)
        val serverNonce = hexToBytes(serverNonceHex)
        val clientNonce = hexToBytes(clientNonceHex)

        var stretched = hmacSha256(pin.toByteArray(Charsets.UTF_8), salt)
        for (i in 1 until 5000) {
            stretched = hmacSha256(pin.toByteArray(Charsets.UTF_8), stretched)
        }

        val clientPrivSeed = MessageDigest.getInstance("SHA-256").digest(
            clientNonce + serverNonce + deviceId.toByteArray(Charsets.UTF_8)
        )
        val clientPk = x25519PublicFromPrivate(clientPrivSeed)
        val maskX = hmacSha256(stretched, "OpenWearSync-PAKE-Mask-X-v1".toByteArray(Charsets.UTF_8))
        val clientMaskedPk = xor32(clientPk, maskX)

        val maskY = hmacSha256(stretched, "OpenWearSync-PAKE-Mask-Y-v1".toByteArray(Charsets.UTF_8))
        val serverPkBytes = if (!serverMaskedPkHex.isNullOrEmpty()) {
            xor32(hexToBytes(serverMaskedPkHex), maskY)
        } else {
            val sSeed = MessageDigest.getInstance("SHA-256").digest(serverNonce + salt)
            x25519PublicFromPrivate(sSeed)
        }

        val dhShared = x25519ScalarMult(clientPrivSeed, serverPkBytes)

        val masterInput = "OpenWearSync-PAKE-SessionKey-v1".toByteArray(Charsets.UTF_8) +
                stretched + serverNonce + clientNonce + serverFingerprint.toByteArray(Charsets.UTF_8)
        val sharedSecret = hmacSha256(dhShared, masterInput)

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
            clientMaskedPkHex = bytesToHex(clientMaskedPk),
        )
    }

    // Authenticated chunk encryption with native acceleration and pure Kotlin fallback
    fun encryptChunk(
        keyBytes: ByteArray,
        nonce: ByteArray,
        chunkIndex: Int,
        payloadBytes: ByteArray,
    ): ByteArray {
        if (isNativeLoaded) {
            try {
                val out = ByteArray(payloadBytes.size + 32)
                val len = nativeEncryptChunk(keyBytes, nonce, chunkIndex, payloadBytes, out)
                if (len > 0) return out
            } catch (_: Throwable) {}
        }

        // JVM Fallback: identical to crates/security encrypt_chunk_payload
        // Keystream: HMAC-SHA256(keyBytes, nonce(16) || chunkIndex_LE(4) || blockIdx_LE(4))
        val ciphertext = ByteArray(payloadBytes.size)
        var blockIdx = 0
        var keystreamBlock = ByteArray(32)

        for (i in payloadBytes.indices) {
            if (i % 32 == 0) {
                val info = ByteArray(24)
                System.arraycopy(nonce, 0, info, 0, 16)
                info[16] = (chunkIndex and 0xFF).toByte()
                info[17] = ((chunkIndex ushr 8) and 0xFF).toByte()
                info[18] = ((chunkIndex ushr 16) and 0xFF).toByte()
                info[19] = ((chunkIndex ushr 24) and 0xFF).toByte()
                info[20] = (blockIdx and 0xFF).toByte()
                info[21] = ((blockIdx ushr 8) and 0xFF).toByte()
                info[22] = ((blockIdx ushr 16) and 0xFF).toByte()
                info[23] = ((blockIdx ushr 24) and 0xFF).toByte()
                keystreamBlock = hmacSha256(keyBytes, info)
                blockIdx++
            }
            ciphertext[i] = (payloadBytes[i].toInt() xor keystreamBlock[i % 32].toInt()).toByte()
        }

        // Tag: HMAC-SHA256(keyBytes, nonce(16) || chunkIndex_LE(4) || ciphertext)
        val tagInput = ByteArray(16 + 4 + ciphertext.size)
        System.arraycopy(nonce, 0, tagInput, 0, 16)
        tagInput[16] = (chunkIndex and 0xFF).toByte()
        tagInput[17] = ((chunkIndex ushr 8) and 0xFF).toByte()
        tagInput[18] = ((chunkIndex ushr 16) and 0xFF).toByte()
        tagInput[19] = ((chunkIndex ushr 24) and 0xFF).toByte()
        System.arraycopy(ciphertext, 0, tagInput, 20, ciphertext.size)
        val tag = hmacSha256(keyBytes, tagInput)

        val out = ByteArray(ciphertext.size + 32)
        System.arraycopy(ciphertext, 0, out, 0, ciphertext.size)
        System.arraycopy(tag, 0, out, ciphertext.size, 32)
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
                val code = nativeCreateTransferSocket(host, port, manifestJson, token)
                if (code == 200 || code == 201) return Pair(code, manifestJson)
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
        handle: Long,
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
                    handle,
                    host,
                    port,
                    transferId,
                    offset,
                    chunkData,
                    if (isEncrypted) 1 else 0,
                    token,
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
            val code = conn.responseCode
            if (code == 200 || code == 201) {
                recordChunk(handle, offset, chunkData.size)
            }
            code
        } catch (_: Exception) {
            0
        }
    }

    fun reconcileSocket(
        handle: Long,
        host: String,
        port: Int,
        transferId: String,
        token: String,
    ): Pair<Int, String?> {
        if (isNativeLoaded) {
            try {
                val code = nativeReconcileSocket(handle, host, port, transferId, token)
                if (code == 200) return Pair(200, """{"result":"reconciled","transfer_id":"$transferId","received":[]}""")
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
                val code = nativeCommitSocket(host, port, transferId, token)
                if (code == 200) return Pair(200, """{"transfer_id":"$transferId","status":"committed"}""")
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

    private val P_25519 = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19))
    private val A24_25519 = BigInteger.valueOf(121665)

    private fun x25519ScalarMult(scalar: ByteArray, uBytes: ByteArray): ByteArray {
        val clamped = scalar.copyOf(32)
        clamped[0] = (clamped[0].toInt() and 248).toByte()
        clamped[31] = (clamped[31].toInt() and 127).toByte()
        clamped[31] = (clamped[31].toInt() or 64).toByte()

        val uRev = ByteArray(32)
        for (i in 0 until 32) uRev[i] = uBytes[31 - i]
        val u = BigInteger(1, uRev).mod(P_25519)

        val x1 = u
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = u
        var z3 = BigInteger.ONE
        var swap = 0

        for (t in 254 downTo 0) {
            val byteIdx = t / 8
            val bitIdx = t % 8
            val bit = ((clamped[byteIdx].toInt() and 0xFF) ushr bitIdx) and 1
            swap = swap xor bit
            if (swap == 1) {
                var tmp = x2; x2 = x3; x3 = tmp
                tmp = z2; z2 = z3; z3 = tmp
            }
            swap = bit

            val a = x2.add(z2).mod(P_25519)
            val aa = a.multiply(a).mod(P_25519)
            val b = x2.subtract(z2).mod(P_25519)
            val bb = b.multiply(b).mod(P_25519)
            val e = aa.subtract(bb).mod(P_25519)
            val c = x3.add(z3).mod(P_25519)
            val d = x3.subtract(z3).mod(P_25519)
            val da = d.multiply(a).mod(P_25519)
            val cb = c.multiply(b).mod(P_25519)

            val x3Next = da.add(cb).mod(P_25519).let { it.multiply(it).mod(P_25519) }
            val z3Next = da.subtract(cb).mod(P_25519).let { it.multiply(it).mod(P_25519) }.multiply(x1).mod(P_25519)
            val x2Next = aa.multiply(bb).mod(P_25519)
            val z2Next = e.multiply(aa.add(A24_25519.multiply(e))).mod(P_25519)

            x2 = x2Next
            z2 = z2Next
            x3 = x3Next
            z3 = z3Next
        }
        if (swap == 1) {
            var tmp = x2; x2 = x3; x3 = tmp
            tmp = z2; z2 = z3; z3 = tmp
        }

        val res = x2.multiply(z2.modInverse(P_25519)).mod(P_25519)
        val resBytes = res.toByteArray()
        val out = ByteArray(32)
        for (i in 0 until 32) {
            val srcIdx = resBytes.size - 1 - i
            out[i] = if (srcIdx >= 0) resBytes[srcIdx] else 0
        }
        return out
    }

    private fun x25519PublicFromPrivate(priv: ByteArray): ByteArray {
        val base = ByteArray(32)
        base[0] = 9
        return x25519ScalarMult(priv, base)
    }

    private fun xor32(a: ByteArray, b: ByteArray): ByteArray {
        val out = ByteArray(32)
        for (i in 0 until 32) {
            out[i] = (a[i].toInt() xor b[i].toInt()).toByte()
        }
        return out
    }

    private fun deriveClientMaskedPk(
        pin: String,
        saltHex: String,
        clientNonceHex: String,
        serverNonceHex: String,
        deviceId: String,
    ): String {
        val salt = hexToBytes(saltHex)
        val serverNonce = hexToBytes(serverNonceHex)
        val clientNonce = hexToBytes(clientNonceHex)
        var stretched = hmacSha256(pin.toByteArray(Charsets.UTF_8), salt)
        for (i in 1 until 5000) {
            stretched = hmacSha256(pin.toByteArray(Charsets.UTF_8), stretched)
        }
        val clientPrivSeed = MessageDigest.getInstance("SHA-256").digest(
            clientNonce + serverNonce + deviceId.toByteArray(Charsets.UTF_8)
        )
        val clientPk = x25519PublicFromPrivate(clientPrivSeed)
        val maskX = hmacSha256(stretched, "OpenWearSync-PAKE-Mask-X-v1".toByteArray(Charsets.UTF_8))
        return bytesToHex(xor32(clientPk, maskX))
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
}

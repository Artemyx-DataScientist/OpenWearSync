package com.openwearsync.wear

import java.io.InputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// START_MODULE_CONTRACT
// PURPOSE: Authenticated, resumable pinned HTTPS transfer engine transferring audio recordings from Wear OS to Windows receiver.
// SCOPE: Deterministic transfer IDs, HMAC-SHA256 authentication tokens, independently pinned TLS enrollment, encrypted chunk streaming, SHA-256 verification, reconciliation, pause/cancel control, and Rust JNI integration.
// DEPENDS: M-WEAR-SHELL, M-ANDROID-PLATFORM, M-TRANSFER-CORE, M-PAIRING-SECURITY
// LINKS: M-WEAR-SHELL, M-TRANSFER-CORE, M-PAIRING-SECURITY, DF-ENCRYPTED-CHUNK-UPLOAD, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   TransferStatus - lifecycle status enum of active transfer.
//   TransferProgress - observable state model of an in-flight transfer.
//   PairingResult - outcome of receiver enrollment attempt with pinned server fingerprint.
//   TransferEngine - pinned HTTPS streaming client executing authenticated chunk uploads, reconciliation, and progress reporting via NativeTransferBridge.
// END_MODULE_MAP

enum class TransferStatus {
    IDLE,
    CONNECTING,
    PAIRING,
    RECONCILING,
    TRANSFERRING,
    PAUSED,
    COMPLETED,
    FAILED,
    CANCELLED,
}

data class TransferProgress(
    val fileName: String = "",
    val transferredBytes: Long = 0L,
    val totalBytes: Long = 0L,
    val percent: Int = 0,
    val status: TransferStatus = TransferStatus.IDLE,
    val errorMessage: String? = null,
)

data class PairingResult(
    val success: Boolean,
    val sharedSecretHex: String? = null,
    val serverFingerprint: String? = null,
    val error: String? = null,
)

class TransferEngine {
    private val isPaused = AtomicBoolean(false)
    private val isCancelled = AtomicBoolean(false)

    fun pause() {
        isPaused.set(true)
    }

    fun resume() {
        isPaused.set(false)
    }

    fun cancel() {
        isCancelled.set(true)
    }

    fun isPaused(): Boolean = isPaused.get()
    fun isCancelled(): Boolean = isCancelled.get()

    companion object {
        fun fromHex(s: String): ByteArray {
            require(s.length % 2 == 0 && s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
            val len = s.length
            val data = ByteArray(len / 2)
            for (i in 0 until len step 2) {
                data[i / 2] = ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
            }
            return data
        }

        fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        // START_CONTRACT: createAuthToken
        // PURPOSE: Compute HMAC-SHA256 authentication token matching Rust openwearsync-security specification.
        // INPUTS: { deviceId: String, sharedSecretHex: String }
        // OUTPUTS: { String - JSON serialized AuthToken }
        // SIDE_EFFECTS: generates 16-byte cryptographically secure random nonce.
        // END_CONTRACT: createAuthToken
        data class TokenData(
            val authHeader: String,
            val nonce: ByteArray,
        )

        fun createAuthTokenData(deviceId: String, sharedSecretHex: String): TokenData {
            require(deviceId.matches(Regex("[A-Za-z0-9_-]{1,128}")))
            require(sharedSecretHex.matches(Regex("[0-9a-fA-F]{64}")))
            val secret = fromHex(sharedSecretHex)
            val now = System.currentTimeMillis() / 1000L
            val nonce = ByteArray(16).apply { SecureRandom().nextBytes(this) }

            val devBytes = deviceId.toByteArray(Charsets.UTF_8)
            val msg = ByteArray(devBytes.size + 8 + 16)
            System.arraycopy(devBytes, 0, msg, 0, devBytes.size)
            for (i in 0..7) {
                msg[devBytes.size + i] = ((now ushr (i * 8)) and 0xFF).toByte()
            }
            System.arraycopy(nonce, 0, msg, devBytes.size + 8, 16)

            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(secret, "HmacSHA256"))
            val sig = mac.doFinal(msg)

            val nonceArray = nonce.joinToString(",") { (it.toInt() and 0xFF).toString() }
            val sigArray = sig.joinToString(",") { (it.toInt() and 0xFF).toString() }

            val json = """{"device_id":"$deviceId","timestamp_epoch_s":$now,"nonce":[$nonceArray],"signature":[$sigArray]}"""
            return TokenData("Bearer $json", nonce)
        }

        fun createAuthToken(deviceId: String, sharedSecretHex: String): String {
            return createAuthTokenData(deviceId, sharedSecretHex).authHeader.removePrefix("Bearer ")
        }

        // START_CONTRACT: computeTransferId
        // PURPOSE: Derive deterministic transfer identity from audio recording file attributes.
        // INPUTS: { descriptor: RecordingDescriptor }
        // OUTPUTS: { String - hex-prefixed transfer identifier }
        // SIDE_EFFECTS: none
        // END_CONTRACT: computeTransferId
        fun computeTransferId(descriptor: RecordingDescriptor): String {
            val input = "${descriptor.displayName}:${descriptor.sizeBytes}:${descriptor.modifiedEpochSeconds}"
            val hash = NativeTransferBridge.computeSha256(input.toByteArray(Charsets.UTF_8))
            return "tx-" + toHex(hash).take(16)
        }
    }

    // START_CONTRACT: TransferEngine::pair
    // PURPOSE: Enroll with a one-use PIN only after independently pinned TLS authentication.
    // INPUTS: Receiver endpoint, device ID/name, PIN and full certificate fingerprint obtained from trusted PC.
    // OUTPUTS: PairingResult containing a random enrollment secret, or failure.
    // SIDE_EFFECTS: Pinned HTTPS enrollment; consumes one receiver session on success.
    // END_CONTRACT: TransferEngine::pair
    fun pair(endpoint: ReceiverEndpoint, deviceId: String, deviceName: String, pin: String,
        pinnedFingerprint: String? = null): PairingResult {
        if (pinnedFingerprint == null || !pinnedFingerprint.matches(Regex("[0-9a-fA-F]{64}")))
            return PairingResult(false, error = "Enter the full certificate fingerprint from the trusted PC first")
        if (!pin.matches(Regex("[0-9]{6}"))) return PairingResult(false, error = "PIN must have six digits")
        val trustedPin = pinnedFingerprint.lowercase()
        val body = "{\"device_id\":${jsonString(deviceId)},\"device_name\":${jsonString(deviceName)},\"pin\":${jsonString(pin)}}"
        val (code, response) = NativeTransferBridge.httpsRequest(endpoint.host, endpoint.port, trustedPin,
            "POST", "/v1/pair/enroll", body = body.toByteArray(Charsets.UTF_8))
        if (code != 200 || response == null) return PairingResult(false, error = "Secure enrollment failed: $code")
        val secret = extractJsonField(response, "shared_secret_hex")
        if (secret == null || !secret.matches(Regex("[0-9a-f]{64}")) || extractJsonField(response, "server_fingerprint") != trustedPin)
            return PairingResult(false, error = "Invalid secure enrollment response")
        return PairingResult(true, secret, trustedPin)
    }

    // START_CONTRACT: TransferEngine::transferRecording
    // PURPOSE: Stream recording chunks to Windows receiver with deterministic ID, native socket I/O, encryption, and commit.
    // INPUTS: { endpoint: ReceiverEndpoint, descriptor: RecordingDescriptor, deviceId: String?, sharedSecretHex: String?, pinnedFingerprint: String?, onProgress: (TransferProgress) -> Unit }
    // OUTPUTS: { Boolean - true if committed successfully }
    // SIDE_EFFECTS: Verifies server fingerprint, manages native session, streams encrypted chunks via Rust socket bridge, and commits.
    // END_CONTRACT: TransferEngine::transferRecording
    fun transferRecording(
        endpoint: ReceiverEndpoint,
        descriptor: RecordingDescriptor,
        deviceId: String? = "galaxy-watch-wearos",
        sharedSecretHex: String? = null,
        pinnedFingerprint: String? = null,
        onProgress: (TransferProgress) -> Unit,
    ): Boolean {
        isPaused.set(false)
        isCancelled.set(false)

        val totalBytes = descriptor.sizeBytes
        val fileName = descriptor.displayName
        val transferId = computeTransferId(descriptor)
        fun requestToken() = if (deviceId != null && sharedSecretHex != null) createAuthTokenData(deviceId, sharedSecretHex) else null

        if (deviceId == null || sharedSecretHex == null || !sharedSecretHex.matches(Regex("[0-9a-fA-F]{64}")) ||
            pinnedFingerprint == null || !pinnedFingerprint.matches(Regex("[0-9a-fA-F]{64}")) || !NativeTransferBridge.isNativeLoaded) {
            onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Protected credentials, native TLS and independent certificate pin required; re-pair if necessary"))
            return false
        }
        val trustedPin = pinnedFingerprint.lowercase()
        val nativeSession = NativeTransferBridge.createSession(totalBytes)
        if (nativeSession == 0L) return false
        try {
        onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.CONNECTING))

        // Authenticate the exact independently obtained certificate before reading or sending audio.
        val (statusCode, statusBody) = NativeTransferBridge.httpsRequest(endpoint.host, endpoint.port, trustedPin, "GET", "/v1/status")
        if (statusCode != 200 || statusBody == null || extractJsonField(statusBody, "server_fingerprint") != trustedPin) {
            onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Cannot authenticate receiver certificate"))
            return false
        }

        // 2. Compute full-file SHA-256
        val digest = MessageDigest.getInstance("SHA-256")
        try {
            descriptor.openStream().use { stream ->
                val buf = ByteArray(64 * 1024)
                var read: Int
                while (stream.read(buf).also { read = it } != -1) {
                    digest.update(buf, 0, read)
                }
            }
        } catch (e: Exception) {
            onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Read error: ${e.message}"))
            return false
        }
        val fullShaHex = toHex(digest.digest())

        // 3. Create transfer on receiver using native socket bridge
        val manifestJson = """{
            "manifest": {
                "transfer_id": "$transferId",
                "file_name": ${jsonString(fileName)},
                "size_bytes": $totalBytes,
                "sha256": "$fullShaHex",
                "modified_at_ms": ${descriptor.modifiedEpochSeconds?.times(1000) ?: System.currentTimeMillis()}
            }
        }""".trimIndent()

        val (createCode, createResp) = NativeTransferBridge.createTransferSocket(
            endpoint.host,
            endpoint.port,
            manifestJson,
            requestToken()?.authHeader ?: "",
            pinnedFingerprint = trustedPin,
        )

        if (createCode != 200 && createCode != 201) {
            onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Create transfer failed: HTTP $createCode ($createResp)"))
            return false
        }

        // 4. Query reconciliation via native socket bridge
        onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.RECONCILING))
        val (recCode, recResp) = NativeTransferBridge.reconcileSocket(
            nativeSession,
            endpoint.host,
            endpoint.port,
            transferId,
            requestToken()?.authHeader ?: "",
            pinnedFingerprint = trustedPin,
        )

        if (recCode != 200 || recResp == null) {
            onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Reconciliation failed: HTTP $recCode"))
            return false
        }

        if (recCode == 200 && recResp != null) {
            val chunkPattern = """"offset"\s*:\s*(\d+)\s*,\s*"length"\s*:\s*(\d+)""".toRegex()
            chunkPattern.findAll(recResp).forEach { match ->
                val offset = match.groupValues[1].toLongOrNull() ?: 0L
                val length = match.groupValues[2].toIntOrNull() ?: 0
                NativeTransferBridge.recordChunk(nativeSession, offset, length)
            }
        }

        val initialTransferred = NativeTransferBridge.getProgress(nativeSession)
        val initialPercent = if (totalBytes > 0) (initialTransferred * 100 / totalBytes).toInt() else 0
        onProgress(TransferProgress(fileName, initialTransferred, totalBytes, initialPercent, TransferStatus.TRANSFERRING))

        // 5. Stream chunks with native socket upload and authenticated encryption
        val chunkSize = 64 * 1024
        var offset = 0L
        val chunkBuf = ByteArray(chunkSize)
        val deviceSecretBytes = sharedSecretHex?.let { fromHex(it) }

        try {
            descriptor.openStream().use { stream ->
                while (true) {
                    var bytesRead = 0
                    while (bytesRead < chunkSize) {
                        val r = stream.read(chunkBuf, bytesRead, chunkSize - bytesRead)
                        if (r == -1) break
                        bytesRead += r
                    }
                    if (bytesRead == 0) break

                    if (isCancelled.get()) {
                        NativeTransferBridge.cancelSession(nativeSession)
                        onProgress(TransferProgress(fileName, offset, totalBytes, (offset * 100 / totalBytes).toInt(), TransferStatus.CANCELLED))
                                    return false
                    }

                    while (isPaused.get()) {
                        NativeTransferBridge.pauseSession(nativeSession)
                        onProgress(TransferProgress(fileName, offset, totalBytes, (offset * 100 / totalBytes).toInt(), TransferStatus.PAUSED))
                        Thread.sleep(250)
                        if (isCancelled.get()) {
                            NativeTransferBridge.cancelSession(nativeSession)
                            onProgress(TransferProgress(fileName, offset, totalBytes, (offset * 100 / totalBytes).toInt(), TransferStatus.CANCELLED))
                                            return false
                        }
                    }
                    NativeTransferBridge.resumeSession(nativeSession)

                    // Skip chunks already acknowledged
                    if (NativeTransferBridge.isChunkReceived(nativeSession, offset, bytesRead)) {
                        offset += bytesRead
                        val currentProgress = NativeTransferBridge.getProgress(nativeSession)
                        val percent = if (totalBytes > 0) (currentProgress * 100 / totalBytes).toInt() else 100
                        onProgress(TransferProgress(fileName, currentProgress, totalBytes, percent, TransferStatus.TRANSFERRING))
                        continue
                    }

                    val rawChunkData = chunkBuf.copyOf(bytesRead)
                    val chunkSha = toHex(NativeTransferBridge.computeSha256(rawChunkData))
                    val chunkIdx = (offset / (64 * 1024L)).toInt()
                    val chunkToken = requestToken()

                    // Encrypt payload if shared secret is available
                    val (payloadToSend, isEncrypted) = if (deviceSecretBytes != null) {
                        Pair(NativeTransferBridge.encryptChunk(deviceSecretBytes, requireNotNull(chunkToken).nonce, chunkIdx, rawChunkData), true)
                    } else {
                        Pair(rawChunkData, false)
                    }

                    // Native socket chunk upload
                    val upCode = NativeTransferBridge.uploadChunkSocket(
                        handle = nativeSession,
                        host = endpoint.host,
                        port = endpoint.port,
                        transferId = transferId,
                        offset = offset,
                        chunkData = payloadToSend,
                        token = chunkToken?.authHeader ?: "",
                        isEncrypted = isEncrypted,
                        sha256Hex = chunkSha,
                        plaintextLength = bytesRead,
                        pinnedFingerprint = trustedPin,
                    )

                    if (upCode != 200) {
                        onProgress(TransferProgress(fileName, offset, totalBytes, (offset * 100 / totalBytes).toInt(), TransferStatus.FAILED, "Chunk upload failed: HTTP $upCode"))
                                    return false
                    }

                    NativeTransferBridge.recordChunk(nativeSession, offset, bytesRead)
                    offset += bytesRead
                    val currentProgress = NativeTransferBridge.getProgress(nativeSession)
                    val percent = if (totalBytes > 0) (currentProgress * 100 / totalBytes).toInt() else 100
                    onProgress(TransferProgress(fileName, currentProgress, totalBytes, percent, TransferStatus.TRANSFERRING))
                }
            }
        } catch (e: Exception) {
            onProgress(TransferProgress(fileName, offset, totalBytes, (offset * 100 / totalBytes).toInt(), TransferStatus.FAILED, "Transfer error: ${e.message}"))
            return false
        }

        // 6. Commit transfer via native socket bridge
        val (commitCode, commitResp) = NativeTransferBridge.commitSocket(
            endpoint.host,
            endpoint.port,
            transferId,
            requestToken()?.authHeader ?: "",
            pinnedFingerprint = trustedPin,
        )

        if (commitCode == 200) {
            onProgress(TransferProgress(fileName, totalBytes, totalBytes, 100, TransferStatus.COMPLETED))
            return true
        } else {
            onProgress(TransferProgress(fileName, totalBytes, totalBytes, 100, TransferStatus.FAILED, "Commit failed: HTTP $commitCode ($commitResp)"))
            return false
        }
        } finally {
            NativeTransferBridge.destroySession(nativeSession)
        }
    }


    private fun extractJsonField(json: String, field: String): String? {
        val pattern = """"$field"\s*:\s*"([^"]+)"""".toRegex()
        return pattern.find(json)?.groupValues?.get(1)
    }
    private fun jsonString(value: String): String = buildString {
        append('"')
        for (c in value) when (c) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            else -> if (c.code < 32) append("\\u%04x".format(c.code)) else append(c)
        }
        append('"')
    }
}

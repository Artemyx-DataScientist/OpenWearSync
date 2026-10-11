package com.openwearsync.wear

import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// START_MODULE_CONTRACT
// PURPOSE: Authenticated, resumable HTTP/socket transfer engine transferring audio recordings from Wear OS to Windows receiver.
// SCOPE: Deterministic transfer IDs, HMAC-SHA256 authentication tokens, zero-knowledge PAKE pairing, encrypted chunk streaming, SHA-256 verification, reconciliation, pause/cancel control, and Rust JNI integration.
// DEPENDS: M-WEAR-SHELL, M-ANDROID-PLATFORM, M-TRANSFER-CORE, M-PAIRING-SECURITY
// LINKS: M-WEAR-SHELL, M-TRANSFER-CORE, M-PAIRING-SECURITY, DF-ENCRYPTED-CHUNK-UPLOAD, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   TransferStatus - lifecycle status enum of active transfer.
//   TransferProgress - observable state model of an in-flight transfer.
//   PairingResult - outcome of receiver enrollment attempt with pinned server fingerprint.
//   TransferEngine - HTTP/socket streaming client executing authenticated chunk uploads, reconciliation, and progress reporting via NativeTransferBridge.
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
    // PURPOSE: Perform Zero-Knowledge PAKE enrollment with Windows receiver, pinning server public key fingerprint.
    // INPUTS: { endpoint: ReceiverEndpoint, deviceId: String, deviceName: String, pin: String, pinnedFingerprint: String? }
    // OUTPUTS: { PairingResult }
    // SIDE_EFFECTS: Executes PAKE mutual challenge-response with rate-limiting and identity pinning.
    // END_CONTRACT: TransferEngine::pair
    fun pair(
        endpoint: ReceiverEndpoint,
        deviceId: String,
        deviceName: String,
        pin: String,
        pinnedFingerprint: String? = null,
    ): PairingResult {
        return try {
            // Step 1: Initiate PAKE handshake
            val initUrl = URL("http://${endpoint.host}:${endpoint.port}/v1/pair/initiate")
            val initConn = (initUrl.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 10_000
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Connection", "close")
            }
            val initBody = """{"device_id":"$deviceId","device_name":"$deviceName"}"""
            initConn.outputStream.use { it.write(initBody.toByteArray(Charsets.UTF_8)) }

            val initCode = initConn.responseCode
            if (initCode == 200) {
                val resp = initConn.inputStream.bufferedReader().use { it.readText() }
                val sessionId = extractJsonField(resp, "session_id") ?: return PairingResult(false, error = "Missing session_id")
                val serverNonceHex = extractJsonField(resp, "server_nonce_hex") ?: return PairingResult(false, error = "Missing server_nonce_hex")
                val saltHex = extractJsonField(resp, "salt_hex") ?: return PairingResult(false, error = "Missing salt_hex")
                val serverMaskedPkHex = extractJsonField(resp, "server_masked_pk_hex")
                val serverFp = extractJsonField(resp, "server_fingerprint") ?: ""

                // Verify pinned fingerprint if previously established
                if (!pinnedFingerprint.isNullOrEmpty() && serverFp.isNotEmpty() && pinnedFingerprint != serverFp) {
                    return PairingResult(false, error = "Server identity mismatch: pinned=$pinnedFingerprint, received=$serverFp")
                }

                // Generate 32-byte client nonce
                val clientNonce = ByteArray(32).apply { SecureRandom().nextBytes(this) }
                val clientNonceHex = toHex(clientNonce)

                // Step 2: Derive PAKE proofs and session shared secret using Native Rust Core
                val pakeResult = NativeTransferBridge.derivePakeKeys(
                    pin = pin.trim(),
                    saltHex = saltHex,
                    serverNonceHex = serverNonceHex,
                    clientNonceHex = clientNonceHex,
                    deviceId = deviceId,
                    serverFingerprint = serverFp,
                    serverMaskedPkHex = serverMaskedPkHex,
                )

                // Step 3: Confirm with client proof and masked ephemeral public key
                val confirmUrl = URL("http://${endpoint.host}:${endpoint.port}/v1/pair/confirm")
                val confirmConn = (confirmUrl.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    doOutput = true
                    connectTimeout = 10_000
                    readTimeout = 10_000
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("Connection", "close")
                }
                val confirmBody = """{
                    "session_id":"$sessionId",
                    "device_id":"$deviceId",
                    "device_name":"$deviceName",
                    "client_nonce_hex":"$clientNonceHex",
                    "client_masked_pk_hex":"${pakeResult.clientMaskedPkHex}",
                    "client_proof_hex":"${pakeResult.clientProofHex}"
                }""".trimIndent()
                confirmConn.outputStream.use { it.write(confirmBody.toByteArray(Charsets.UTF_8)) }

                val confirmCode = confirmConn.responseCode
                if (confirmCode == 200) {
                    val confResp = confirmConn.inputStream.bufferedReader().use { it.readText() }
                    val receivedServerProof = extractJsonField(confResp, "server_proof_hex") ?: ""
                    // Mutual verification: server must demonstrate knowledge of PAKE proof
                    if (receivedServerProof != pakeResult.serverProofHex) {
                        return PairingResult(false, error = "Server proof verification failed (invalid server)")
                    }
                    val confirmedFp = extractJsonField(confResp, "server_fingerprint") ?: serverFp
                    PairingResult(
                        success = true,
                        sharedSecretHex = pakeResult.sharedSecretHex,
                        serverFingerprint = confirmedFp,
                    )
                } else {
                    val err = confirmConn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $confirmCode"
                    PairingResult(false, error = err)
                }
            } else {
                val err = initConn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $initCode"
                PairingResult(false, error = "Initiate pairing failed: $err")
            }
        } catch (e: Exception) {
            PairingResult(success = false, error = e.message ?: "Connection failed")
        }
    }

    private fun getAuthHeader(deviceId: String?, sharedSecretHex: String?): String? {
        if (deviceId == null || sharedSecretHex == null) return null
        return "Bearer ${createAuthToken(deviceId, sharedSecretHex)}"
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
        val tokenData = if (deviceId != null && sharedSecretHex != null) createAuthTokenData(deviceId, sharedSecretHex) else null
        val token = tokenData?.authHeader ?: ""
        val tokenNonce = tokenData?.nonce ?: ByteArray(16)

        val nativeSession = NativeTransferBridge.createSession(totalBytes)
        onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.CONNECTING))

        // 1. Verify receiver identity and pinned fingerprint
        try {
            val statusUrl = URL("http://${endpoint.host}:${endpoint.port}/v1/status")
            val statusConn = (statusUrl.openConnection() as HttpURLConnection).apply {
                connectTimeout = 5_000
                readTimeout = 5_000
                setRequestProperty("Connection", "close")
            }
            if (statusConn.responseCode == 200) {
                val statusBody = statusConn.inputStream.bufferedReader().use { it.readText() }
                val serverFp = extractJsonField(statusBody, "server_fingerprint")
                if (!pinnedFingerprint.isNullOrEmpty() && !serverFp.isNullOrEmpty() && serverFp != pinnedFingerprint) {
                    onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Server identity changed! Pinned fingerprint mismatch."))
                    NativeTransferBridge.destroySession(nativeSession)
                    return false
                }
            }
        } catch (e: Exception) {
            onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Cannot connect to receiver: ${e.message}"))
            NativeTransferBridge.destroySession(nativeSession)
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
            NativeTransferBridge.destroySession(nativeSession)
            return false
        }
        val fullShaHex = toHex(digest.digest())

        // 3. Create transfer on receiver using native socket bridge
        val manifestJson = """{
            "manifest": {
                "transfer_id": "$transferId",
                "file_name": "$fileName",
                "size_bytes": $totalBytes,
                "sha256": "$fullShaHex",
                "modified_at_ms": ${descriptor.modifiedEpochSeconds?.times(1000) ?: System.currentTimeMillis()}
            }
        }""".trimIndent()

        val (createCode, createResp) = NativeTransferBridge.createTransferSocket(
            endpoint.host,
            endpoint.port,
            manifestJson,
            token,
        )

        if (createCode != 200 && createCode != 201 && createCode != 409) {
            onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Create transfer failed: HTTP $createCode ($createResp)"))
            NativeTransferBridge.destroySession(nativeSession)
            return false
        }

        // 4. Query reconciliation via native socket bridge
        onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.RECONCILING))
        val (recCode, recResp) = NativeTransferBridge.reconcileSocket(
            nativeSession,
            endpoint.host,
            endpoint.port,
            transferId,
            token,
        )

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
                var bytesRead: Int
                while (stream.read(chunkBuf).also { bytesRead = it } != -1) {
                    if (isCancelled.get()) {
                        NativeTransferBridge.cancelSession(nativeSession)
                        onProgress(TransferProgress(fileName, offset, totalBytes, (offset * 100 / totalBytes).toInt(), TransferStatus.CANCELLED))
                        NativeTransferBridge.destroySession(nativeSession)
                        return false
                    }

                    while (isPaused.get()) {
                        NativeTransferBridge.pauseSession(nativeSession)
                        onProgress(TransferProgress(fileName, offset, totalBytes, (offset * 100 / totalBytes).toInt(), TransferStatus.PAUSED))
                        Thread.sleep(250)
                        if (isCancelled.get()) {
                            NativeTransferBridge.cancelSession(nativeSession)
                            onProgress(TransferProgress(fileName, offset, totalBytes, (offset * 100 / totalBytes).toInt(), TransferStatus.CANCELLED))
                            NativeTransferBridge.destroySession(nativeSession)
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

                    // Encrypt payload if shared secret is available
                    val (payloadToSend, isEncrypted) = if (deviceSecretBytes != null) {
                        Pair(NativeTransferBridge.encryptChunk(deviceSecretBytes, tokenNonce, chunkIdx, rawChunkData), true)
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
                        token = token,
                        isEncrypted = isEncrypted,
                        sha256Hex = chunkSha,
                    )

                    if (upCode != 200) {
                        onProgress(TransferProgress(fileName, offset, totalBytes, (offset * 100 / totalBytes).toInt(), TransferStatus.FAILED, "Chunk upload failed: HTTP $upCode"))
                        NativeTransferBridge.destroySession(nativeSession)
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
            NativeTransferBridge.destroySession(nativeSession)
            return false
        }

        // 6. Commit transfer via native socket bridge
        val (commitCode, commitResp) = NativeTransferBridge.commitSocket(
            endpoint.host,
            endpoint.port,
            transferId,
            token,
        )

        if (commitCode == 200) {
            onProgress(TransferProgress(fileName, totalBytes, totalBytes, 100, TransferStatus.COMPLETED))
            NativeTransferBridge.destroySession(nativeSession)
            return true
        } else {
            onProgress(TransferProgress(fileName, totalBytes, totalBytes, 100, TransferStatus.FAILED, "Commit failed: HTTP $commitCode ($commitResp)"))
            NativeTransferBridge.destroySession(nativeSession)
            return false
        }
    }

    private fun extractJsonField(json: String, field: String): String? {
        val pattern = """"$field"\s*:\s*"([^"]+)"""".toRegex()
        return pattern.find(json)?.groupValues?.get(1)
    }
}

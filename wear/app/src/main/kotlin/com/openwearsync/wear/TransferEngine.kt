package com.openwearsync.wear

import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// START_MODULE_CONTRACT
// PURPOSE: Authenticated, resumable HTTP transfer engine transferring audio recordings from Wear OS to Windows receiver.
// SCOPE: Deterministic transfer IDs, HMAC-SHA256 authentication tokens, chunk streaming, SHA-256 verification, reconciliation, pause/cancel control, PIN pairing, and Rust JNI integration.
// DEPENDS: M-WEAR-SHELL, M-ANDROID-PLATFORM, M-TRANSFER-CORE, M-PAIRING-SECURITY
// LINKS: M-WEAR-SHELL, M-TRANSFER-CORE, M-PAIRING-SECURITY, DF-ENCRYPTED-CHUNK-UPLOAD, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   TransferStatus - lifecycle status enum of active transfer.
//   TransferProgress - observable state model of an in-flight transfer.
//   PairingResult - outcome of receiver enrollment attempt with pinned server fingerprint.
//   TransferEngine - HTTP streaming client executing authenticated chunk uploads, reconciliation, and progress reporting via NativeTransferBridge.
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
        fun createAuthToken(deviceId: String, sharedSecretHex: String): String {
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

            return """{"device_id":"$deviceId","timestamp_epoch_s":$now,"nonce":[$nonceArray],"signature":[$sigArray]}"""
        }

        // START_CONTRACT: computeTransferId
        // PURPOSE: Derive deterministic transfer identity from audio recording file attributes.
        // INPUTS: { descriptor: RecordingDescriptor }
        // OUTPUTS: { String - hex-prefixed transfer identifier }
        // SIDE_EFFECTS: none
        // END_CONTRACT: computeTransferId
        fun computeTransferId(descriptor: RecordingDescriptor): String {
            val input = "${descriptor.displayName}:${descriptor.sizeBytes}:${descriptor.modifiedEpochSeconds}"
            val hash = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
            return "tx-" + toHex(hash).take(16)
        }
    }

    // START_CONTRACT: TransferEngine::pair
    // PURPOSE: Perform PIN-based enrollment with Windows receiver over HTTP REST endpoint.
    // INPUTS: { endpoint: ReceiverEndpoint, deviceId: String, deviceName: String, pin: String }
    // OUTPUTS: { PairingResult }
    // SIDE_EFFECTS: Sends HTTP POST to receiver /v1/pair endpoint, derives shared secret locally.
    // END_CONTRACT: TransferEngine::pair
    fun pair(
        endpoint: ReceiverEndpoint,
        deviceId: String,
        deviceName: String,
        pin: String,
    ): PairingResult {
        return try {
            val url = URL("http://${endpoint.host}:${endpoint.port}/v1/pair")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 10_000
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Connection", "close")
            }

            val jsonBody = """{"device_id":"$deviceId","device_name":"$deviceName","pin":"$pin"}"""
            conn.outputStream.use { os ->
                os.write(jsonBody.toByteArray(Charsets.UTF_8))
            }

            val code = conn.responseCode
            if (code == 200) {
                val resp = conn.inputStream.bufferedReader().use { it.readText() }
                val fingerprint = extractJsonField(resp, "server_fingerprint") ?: ""
                val derivedSecret = NativeTransferBridge.deriveSharedSecret(pin, deviceId)
                val secretHex = toHex(derivedSecret)
                PairingResult(success = true, sharedSecretHex = secretHex, serverFingerprint = fingerprint)
            } else {
                val err = conn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $code"
                PairingResult(success = false, error = err)
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
    // PURPOSE: Stream recording chunks to Windows receiver with deterministic ID, reconciliation, SHA-256 verification, and commit.
    // INPUTS: { endpoint: ReceiverEndpoint, descriptor: RecordingDescriptor, deviceId: String?, sharedSecretHex: String?, pinnedFingerprint: String?, onProgress: (TransferProgress) -> Unit }
    // OUTPUTS: { Boolean - true if committed successfully }
    // SIDE_EFFECTS: Queries status/fingerprint, creates transfer, reconciles chunks, uploads missing chunks, commits to receiver.
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

        val nativeSession = NativeTransferBridge.createSession(totalBytes)

        onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.CONNECTING))

        // 1. Verify receiver identity / pinned fingerprint
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

        // 3. Create transfer on receiver (or detect if already created)
        var transferCreatedOrExists = false
        try {
            val createUrl = URL("http://${endpoint.host}:${endpoint.port}/v1/transfers")
            val createConn = (createUrl.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 10_000
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Connection", "close")
                getAuthHeader(deviceId, sharedSecretHex)?.let { setRequestProperty("Authorization", it) }
            }

            val manifestJson = """{
                "manifest": {
                    "transfer_id": "$transferId",
                    "file_name": "$fileName",
                    "size_bytes": $totalBytes,
                    "sha256": "$fullShaHex",
                    "modified_at_ms": ${descriptor.modifiedEpochSeconds?.times(1000) ?: System.currentTimeMillis()}
                }
            }""".trimIndent()

            createConn.outputStream.use { it.write(manifestJson.toByteArray(Charsets.UTF_8)) }
            val createCode = createConn.responseCode
            if (createCode == 200 || createCode == 201) {
                transferCreatedOrExists = true
            } else if (createCode == 409) {
                // Transfer already initialized on receiver, safe to resume
                transferCreatedOrExists = true
            } else {
                val err = createConn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $createCode"
                onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Create failed: $err"))
                NativeTransferBridge.destroySession(nativeSession)
                return false
            }
        } catch (e: Exception) {
            onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Network error: ${e.message}"))
            NativeTransferBridge.destroySession(nativeSession)
            return false
        }

        // 4. Query reconciliation to register chunks receiver already has
        onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.RECONCILING))
        try {
            val recUrl = URL("http://${endpoint.host}:${endpoint.port}/v1/transfers/$transferId/reconcile")
            val recConn = (recUrl.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 8_000
                readTimeout = 8_000
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Connection", "close")
                getAuthHeader(deviceId, sharedSecretHex)?.let { setRequestProperty("Authorization", it) }
            }
            recConn.outputStream.use { it.write("{}".toByteArray(Charsets.UTF_8)) }

            if (recConn.responseCode == 200) {
                val recBody = recConn.inputStream.bufferedReader().use { it.readText() }
                val chunkPattern = """"offset"\s*:\s*(\d+)\s*,\s*"length"\s*:\s*(\d+)""".toRegex()
                chunkPattern.findAll(recBody).forEach { match ->
                    val offset = match.groupValues[1].toLongOrNull() ?: 0L
                    val length = match.groupValues[2].toIntOrNull() ?: 0
                    NativeTransferBridge.recordChunk(nativeSession, offset, length)
                }
            }
        } catch (_: Exception) {
            // Non-fatal, reconciliation simply starts from 0 acknowledged
        }

        val initialTransferred = NativeTransferBridge.getProgress(nativeSession)
        val initialPercent = if (totalBytes > 0) (initialTransferred * 100 / totalBytes).toInt() else 0
        onProgress(TransferProgress(fileName, initialTransferred, totalBytes, initialPercent, TransferStatus.TRANSFERRING))

        // 5. Upload missing chunks
        val chunkSize = 64 * 1024
        var offset = 0L
        val chunkBuf = ByteArray(chunkSize)

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

                    // Skip chunks already stored on receiver
                    if (NativeTransferBridge.isChunkReceived(nativeSession, offset, bytesRead)) {
                        offset += bytesRead
                        val currentProgress = NativeTransferBridge.getProgress(nativeSession)
                        val percent = if (totalBytes > 0) (currentProgress * 100 / totalBytes).toInt() else 100
                        onProgress(TransferProgress(fileName, currentProgress, totalBytes, percent, TransferStatus.TRANSFERRING))
                        continue
                    }

                    val chunkSha = toHex(MessageDigest.getInstance("SHA-256").digest(chunkBuf.copyOf(bytesRead)))
                    val uploadUrl = URL("http://${endpoint.host}:${endpoint.port}/v1/transfers/$transferId/chunks/$offset")
                    val uploadConn = (uploadUrl.openConnection() as HttpURLConnection).apply {
                        requestMethod = "PUT"
                        doOutput = true
                        connectTimeout = 10_000
                        readTimeout = 15_000
                        setRequestProperty("Content-Type", "application/octet-stream")
                        setRequestProperty("Connection", "close")
                        setRequestProperty("x-chunk-sha256", chunkSha)
                        getAuthHeader(deviceId, sharedSecretHex)?.let { setRequestProperty("Authorization", it) }
                    }

                    uploadConn.outputStream.use { it.write(chunkBuf, 0, bytesRead) }
                    val upCode = uploadConn.responseCode
                    if (upCode != 200) {
                        val err = uploadConn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $upCode"
                        onProgress(TransferProgress(fileName, offset, totalBytes, (offset * 100 / totalBytes).toInt(), TransferStatus.FAILED, "Chunk failed: $err"))
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

        // 6. Commit transfer on receiver
        try {
            val commitUrl = URL("http://${endpoint.host}:${endpoint.port}/v1/transfers/$transferId/commit")
            val commitConn = (commitUrl.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 10_000
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Connection", "close")
                getAuthHeader(deviceId, sharedSecretHex)?.let { setRequestProperty("Authorization", it) }
            }
            commitConn.outputStream.use { it.write("{}".toByteArray(Charsets.UTF_8)) }

            val commitCode = commitConn.responseCode
            if (commitCode == 200) {
                onProgress(TransferProgress(fileName, totalBytes, totalBytes, 100, TransferStatus.COMPLETED))
                NativeTransferBridge.destroySession(nativeSession)
                return true
            } else {
                val err = commitConn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $commitCode"
                onProgress(TransferProgress(fileName, totalBytes, totalBytes, 100, TransferStatus.FAILED, "Commit failed: $err"))
                NativeTransferBridge.destroySession(nativeSession)
                return false
            }
        } catch (e: Exception) {
            onProgress(TransferProgress(fileName, totalBytes, totalBytes, 100, TransferStatus.FAILED, "Commit error: ${e.message}"))
            NativeTransferBridge.destroySession(nativeSession)
            return false
        }
    }

    private fun extractJsonField(json: String, field: String): String? {
        val pattern = """"$field"\s*:\s*"([^"]+)"""".toRegex()
        return pattern.find(json)?.groupValues?.get(1)
    }
}

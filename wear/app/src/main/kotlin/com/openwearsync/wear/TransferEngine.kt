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
// SCOPE: Deterministic transfer IDs, HMAC-SHA256 authentication tokens, chunk streaming, SHA-256 verification, reconciliation, pause/cancel control, and PIN pairing.
// DEPENDS: M-WEAR-SHELL, M-ANDROID-PLATFORM, M-TRANSFER-CORE, M-PAIRING-SECURITY
// LINKS: M-WEAR-SHELL, M-TRANSFER-CORE, M-PAIRING-SECURITY, DF-ENCRYPTED-CHUNK-UPLOAD, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   TransferStatus - lifecycle status enum of active transfer.
//   TransferProgress - observable state model of an in-flight transfer.
//   PairingResult - outcome of receiver enrollment attempt.
//   TransferEngine - HTTP streaming client executing authenticated chunk uploads, reconciliation, and progress reporting.
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
    // SIDE_EFFECTS: Sends HTTP POST to receiver /v1/pair endpoint.
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
                val secretHex = extractJsonField(resp, "shared_secret_hex") ?: ""
                PairingResult(success = true, sharedSecretHex = secretHex)
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
    // INPUTS: { endpoint: ReceiverEndpoint, descriptor: RecordingDescriptor, deviceId: String?, sharedSecretHex: String?, onProgress: (TransferProgress) -> Unit }
    // OUTPUTS: { Boolean - true if committed successfully }
    // SIDE_EFFECTS: Queries reconciliation, creates transfer if needed, uploads missing chunks, commits to receiver.
    // END_CONTRACT: TransferEngine::transferRecording
    fun transferRecording(
        endpoint: ReceiverEndpoint,
        descriptor: RecordingDescriptor,
        deviceId: String? = "galaxy-watch-wearos",
        sharedSecretHex: String? = null,
        onProgress: (TransferProgress) -> Unit,
    ): Boolean {
        isPaused.set(false)
        isCancelled.set(false)

        val totalBytes = descriptor.sizeBytes
        val fileName = descriptor.displayName
        val transferId = computeTransferId(descriptor)

        onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.CONNECTING))

        // 1. Compute full-file SHA-256
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

        // 2. Query reconciliation to check if transfer exists and which chunks were already received
        onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.RECONCILING))
        val alreadyReceivedOffsets = mutableSetOf<Long>()
        var transferExistsOnReceiver = false

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
                transferExistsOnReceiver = true
                val recBody = recConn.inputStream.bufferedReader().use { it.readText() }
                // Parse received chunks: {"result":"reconciled","received":[{"offset":0,...},...]}
                val offsetRegex = """"offset"\s*:\s*(\d+)""".toRegex()
                offsetRegex.findAll(recBody).forEach { match ->
                    match.groupValues[1].toLongOrNull()?.let { alreadyReceivedOffsets.add(it) }
                }
            }
        } catch (_: Exception) {
            // Receiver might not have this transfer yet, proceed to create
        }

        // 3. Create transfer if not already present on receiver
        if (!transferExistsOnReceiver) {
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
                        "modified_at_ms": ${System.currentTimeMillis()}
                    }
                }""".trimIndent()

                createConn.outputStream.use { it.write(manifestJson.toByteArray(Charsets.UTF_8)) }
                val createCode = createConn.responseCode
                if (createCode != 200 && createCode != 201) {
                    val err = createConn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $createCode"
                    onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Create failed: $err"))
                    return false
                }
            } catch (e: Exception) {
                onProgress(TransferProgress(fileName, 0L, totalBytes, 0, TransferStatus.FAILED, "Network error: ${e.message}"))
                return false
            }
        }

        // 4. Upload chunks (skipping already acknowledged chunks)
        val chunkSize = 64 * 1024
        var transferred = 0L
        val chunkBuf = ByteArray(chunkSize)

        try {
            descriptor.openStream().use { stream ->
                var bytesRead: Int
                while (stream.read(chunkBuf).also { bytesRead = it } != -1) {
                    if (isCancelled.get()) {
                        onProgress(TransferProgress(fileName, transferred, totalBytes, (transferred * 100 / totalBytes).toInt(), TransferStatus.CANCELLED))
                        return false
                    }

                    while (isPaused.get()) {
                        onProgress(TransferProgress(fileName, transferred, totalBytes, (transferred * 100 / totalBytes).toInt(), TransferStatus.PAUSED))
                        Thread.sleep(250)
                        if (isCancelled.get()) {
                            onProgress(TransferProgress(fileName, transferred, totalBytes, (transferred * 100 / totalBytes).toInt(), TransferStatus.CANCELLED))
                            return false
                        }
                    }

                    // Check if chunk is already stored on receiver
                    if (alreadyReceivedOffsets.contains(transferred)) {
                        transferred += bytesRead
                        val percent = if (totalBytes > 0) (transferred * 100 / totalBytes).toInt() else 100
                        onProgress(TransferProgress(fileName, transferred, totalBytes, percent, TransferStatus.TRANSFERRING))
                        continue
                    }

                    val chunkSha = toHex(MessageDigest.getInstance("SHA-256").digest(chunkBuf.copyOf(bytesRead)))
                    val uploadUrl = URL("http://${endpoint.host}:${endpoint.port}/v1/transfers/$transferId/chunks/$transferred")
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
                        onProgress(TransferProgress(fileName, transferred, totalBytes, (transferred * 100 / totalBytes).toInt(), TransferStatus.FAILED, "Chunk failed: $err"))
                        return false
                    }

                    transferred += bytesRead
                    val percent = if (totalBytes > 0) (transferred * 100 / totalBytes).toInt() else 100
                    onProgress(TransferProgress(fileName, transferred, totalBytes, percent, TransferStatus.TRANSFERRING))
                }
            }
        } catch (e: Exception) {
            onProgress(TransferProgress(fileName, transferred, totalBytes, (transferred * 100 / totalBytes).toInt(), TransferStatus.FAILED, "Transfer error: ${e.message}"))
            return false
        }

        // 5. Commit transfer on receiver
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
            if (commitCode != 200) {
                val err = commitConn.errorStream?.bufferedReader()?.use { it.readText() } ?: "HTTP $commitCode"
                onProgress(TransferProgress(fileName, transferred, totalBytes, 100, TransferStatus.FAILED, "Commit failed: $err"))
                return false
            }
        } catch (e: Exception) {
            onProgress(TransferProgress(fileName, transferred, totalBytes, 100, TransferStatus.FAILED, "Commit error: ${e.message}"))
            return false
        }

        onProgress(TransferProgress(fileName, totalBytes, totalBytes, 100, TransferStatus.COMPLETED))
        return true
    }

    private fun extractJsonField(json: String, field: String): String? {
        val pattern = "\"$field\"\\s*:\\s*\"([^\"]+)\"".toRegex()
        return pattern.find(json)?.groupValues?.get(1)
    }
}

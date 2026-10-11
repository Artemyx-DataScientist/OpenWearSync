package com.openwearsync.wear

import java.io.InputStream

// START_MODULE_CONTRACT
// PURPOSE: Expose unprivileged recording metadata and lazy streams from an Android content provider.
// SCOPE: Readiness filtering and provider access only; transfer and persistence are owned elsewhere.
// DEPENDS: M-WEAR-SHELL, M-ANDROID-PLATFORM
// LINKS: M-WEAR-SHELL, M-ANDROID-PLATFORM, V-M-ANDROID-PLATFORM, DF-RECORDING-MANIFEST
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   RecordingReadinessAdapter - filters provider records into safe, lazy-to-open descriptors.
//   RecordingProvider - narrow content-provider boundary used by Android and deterministic tests.
// END_MODULE_MAP

enum class Stability {
    STABLE,
    IN_PROGRESS,
    UNKNOWN,
}

data class SourceRecord(
    val uri: String,
    val displayName: String,
    val mimeType: String?,
    val sizeBytes: Long?,
    val stability: Stability,
    val modifiedEpochSeconds: Long? = null,
)

interface RecordingProvider {
    // START_CONTRACT: listRecords
    // PURPOSE: Return metadata visible through the provider without opening file contents.
    // INPUTS: none
    // OUTPUTS: { List<SourceRecord> - provider metadata only }
    // SIDE_EFFECTS: May fail with SecurityException when user access was revoked.
    // END_CONTRACT: listRecords
    fun listRecords(): List<SourceRecord>

    // START_CONTRACT: openStream
    // PURPOSE: Open a bounded streaming descriptor for one provider URI.
    // INPUTS: { uri: String - provider URI returned by listRecords }
    // OUTPUTS: { InputStream - lazy stream owned by the caller }
    // SIDE_EFFECTS: Opens provider-backed content; never buffers the full recording.
    // END_CONTRACT: openStream
    fun openStream(uri: String): InputStream
}

data class RecordingDescriptor(
    val uri: String,
    val displayName: String,
    val mimeType: String?,
    val sizeBytes: Long,
    val modifiedEpochSeconds: Long?,
    private val streamOpener: () -> InputStream,
) {
    fun openStream(): InputStream = streamOpener()
}

data class SkippedRecording(
    val uri: String,
    val reason: Reason,
) {
    enum class Reason {
        IN_PROGRESS,
        UNKNOWN_STABILITY,
        NOT_AUDIO,
        INVALID_SIZE,
    }
}

sealed interface ReadinessBlock {
    data class NoAccess(val message: String) : ReadinessBlock
    data class ProviderUnavailable(val message: String) : ReadinessBlock
}

data class ReadinessScanResult(
    val ready: List<RecordingDescriptor>,
    val skipped: List<SkippedRecording>,
    val block: ReadinessBlock? = null,
)

object AudioContainerInspector {
    // START_CONTRACT: AudioContainerInspector::isM4aContainerFinalized
    // PURPOSE: Inspect ISO base media (M4A/MP4) byte stream to verify container closure and presence of moov atom.
    // INPUTS: { stream: InputStream }
    // OUTPUTS: { Boolean - true if header is valid and container is finalized }
    // SIDE_EFFECTS: Reads bounded header bytes from the input stream.
    // END_CONTRACT: AudioContainerInspector::isM4aContainerFinalized
    fun isM4aContainerFinalized(stream: InputStream): Boolean {
        return try {
            val header = ByteArray(8)
            val bytesRead = stream.read(header)
            if (bytesRead < 8) return false

            val boxLen = ((header[0].toInt() and 0xFF) shl 24) or
                    ((header[1].toInt() and 0xFF) shl 16) or
                    ((header[2].toInt() and 0xFF) shl 8) or
                    (header[3].toInt() and 0xFF)
            val boxType = String(header, 4, 4, Charsets.US_ASCII)

            if (boxType == "ftyp") {
                val remainingInBox = (boxLen - 8).toLong()
                if (remainingInBox > 0) {
                    stream.skip(remainingInBox)
                }

                var scanned = 0L
                val maxScan = 2 * 1024 * 1024L
                while (scanned < maxScan) {
                    val nextHeader = ByteArray(8)
                    val r = stream.read(nextHeader)
                    if (r < 8) break
                    scanned += 8

                    val nextLen = ((nextHeader[0].toInt() and 0xFF).toLong() shl 24) or
                            ((nextHeader[1].toInt() and 0xFF).toLong() shl 16) or
                            ((nextHeader[2].toInt() and 0xFF).toLong() shl 8) or
                            (nextHeader[3].toInt() and 0xFF).toLong()
                    val nextType = String(nextHeader, 4, 4, Charsets.US_ASCII)

                    if (nextType == "moov") {
                        return true
                    }
                    if (nextLen == 0L) {
                        break
                    }
                    val skipBytes = nextLen - 8
                    if (skipBytes > 0) {
                        stream.skip(skipBytes)
                        scanned += skipBytes
                    }
                }
                false
            } else if (boxType == "moov") {
                true
            } else if (header.take(4).toByteArray().contentEquals(byteArrayOf('R'.code.toByte(), 'I'.code.toByte(), 'F'.code.toByte(), 'F'.code.toByte()))) {
                true
            } else if (header.take(5).toByteArray().contentEquals("#!AMR".toByteArray(Charsets.US_ASCII))) {
                true
            } else {
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}

class RecordingReadinessAdapter(
    private val provider: RecordingProvider,
    private val verifyContainer: Boolean = false,
) {
    // START_CONTRACT: scan
    // PURPOSE: Identify completed audio recordings while preserving unknown or unsafe entries for diagnostics.
    // INPUTS: none
    // OUTPUTS: { ReadinessScanResult - ready descriptors, skipped reasons, and access block }
    // SIDE_EFFECTS: Reads provider metadata only; content is opened only through a returned descriptor.
    // END_CONTRACT: scan
    fun scan(): ReadinessScanResult {
        val records = try {
            provider.listRecords()
        } catch (error: SecurityException) {
            return ReadinessScanResult(emptyList(), emptyList(), ReadinessBlock.NoAccess(error.message ?: "recording access revoked"))
        } catch (error: RuntimeException) {
            return ReadinessScanResult(emptyList(), emptyList(), ReadinessBlock.ProviderUnavailable(error.message ?: "recording provider unavailable"))
        }

        val ready = mutableListOf<RecordingDescriptor>()
        val skipped = mutableListOf<SkippedRecording>()
        records.forEach { record ->
            when {
                record.stability == Stability.IN_PROGRESS -> skipped += SkippedRecording(record.uri, SkippedRecording.Reason.IN_PROGRESS)
                record.stability == Stability.UNKNOWN -> skipped += SkippedRecording(record.uri, SkippedRecording.Reason.UNKNOWN_STABILITY)
                record.mimeType?.startsWith("audio/") != true -> skipped += SkippedRecording(record.uri, SkippedRecording.Reason.NOT_AUDIO)
                record.sizeBytes == null || record.sizeBytes <= 0L -> skipped += SkippedRecording(record.uri, SkippedRecording.Reason.INVALID_SIZE)
                verifyContainer && record.mimeType == "audio/mp4" && !AudioContainerInspector.isM4aContainerFinalized(provider.openStream(record.uri)) -> {
                    skipped += SkippedRecording(record.uri, SkippedRecording.Reason.IN_PROGRESS)
                }
                else -> ready += RecordingDescriptor(
                    uri = record.uri,
                    displayName = record.displayName,
                    mimeType = record.mimeType,
                    sizeBytes = record.sizeBytes,
                    modifiedEpochSeconds = record.modifiedEpochSeconds,
                    streamOpener = { provider.openStream(record.uri) },
                )
            }
        }
        return ReadinessScanResult(ready, skipped)
    }
}


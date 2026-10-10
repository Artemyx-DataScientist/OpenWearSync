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

class RecordingReadinessAdapter(private val provider: RecordingProvider) {
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

package com.openwearsync.wear

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RecordingReadinessTest {
    @Test
    fun excludesPendingRecordings_and_marksUnknownStability() {
        val provider = FakeRecordingProvider(
            records = listOf(
                SourceRecord("content://voice/ready", "ready.m4a", "audio/mp4", 12_000L, Stability.STABLE),
                SourceRecord("content://voice/pending", "pending.m4a", "audio/mp4", 4_000L, Stability.IN_PROGRESS),
                SourceRecord("content://voice/unknown", "unknown.m4a", "audio/mp4", 0L, Stability.UNKNOWN),
            ),
        )

        val result = RecordingReadinessAdapter(provider).scan()

        assertEquals(listOf("content://voice/ready"), result.ready.map { it.uri })
        assertEquals(
            setOf(
                SkippedRecording.Reason.IN_PROGRESS,
                SkippedRecording.Reason.UNKNOWN_STABILITY,
            ),
            result.skipped.map { it.reason }.toSet(),
        )
    }

    @Test
    fun revokedProviderAccess_isReportedAsNoAccessBlock() {
        val provider = FakeRecordingProvider(accessError = SecurityException("revoked"))

        val result = RecordingReadinessAdapter(provider).scan()

        val blocked = assertIs<ReadinessBlock.NoAccess>(result.block)
        assertTrue(blocked.message.contains("revoked"))
        assertTrue(result.ready.isEmpty())
    }

    @Test
    fun descriptorOpensProviderStream_withoutBufferingTheWholeRecording() {
        val provider = FakeRecordingProvider(
            records = listOf(SourceRecord("content://voice/large", "large.m4a", "audio/mp4", 2_000_000_000L, Stability.STABLE)),
        )

        val descriptor = assertNotNull(RecordingReadinessAdapter(provider).scan().ready.single())
        assertEquals(0, provider.openCount)
        descriptor.openStream().use { stream ->
            assertEquals('a'.code, stream.read())
        }
        assertEquals(1, provider.openCount)
    }

    private class FakeRecordingProvider(
        private val records: List<SourceRecord> = emptyList(),
        private val accessError: SecurityException? = null,
    ) : RecordingProvider {
        var openCount: Int = 0
            private set

        override fun listRecords(): List<SourceRecord> {
            accessError?.let { throw it }
            return records
        }

        override fun openStream(uri: String) = java.io.ByteArrayInputStream(byteArrayOf('a'.code.toByte()))
            .also { openCount++ }
    }
}

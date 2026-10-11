package com.openwearsync.wear

import org.junit.Assert.*
import org.junit.Test

// START_MODULE_CONTRACT
// PURPOSE: Unit tests for NativeTransferBridge, independent pin enforcement, encrypted chunks, and transfer security.
// SCOPE: Offline deterministic verification of cryptographic contracts without requiring hardware watch.
// DEPENDS: M-TRANSFER-CORE, M-PAIRING-SECURITY, M-ANDROID-PLATFORM
// LINKS: M-TRANSFER-CORE, M-PAIRING-SECURITY, V-M-PAIRING-SECURITY
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   TransferEngineAndSecurityTest - unit test suite for native transfer bridge and security.
// END_MODULE_MAP

class TransferEngineAndSecurityTest {

    @Test
    fun pairingRequiresAnIndependentPinBeforeAnyNetworkRequest() {
        val result = TransferEngine().pair(ReceiverEndpoint("127.0.0.1", 1), "watch", "Watch", "123456")
        assertFalse(result.success)
        assertTrue(result.error!!.contains("fingerprint"))
    }

    @Test
    fun testChunkEncryptionGeneratesAuthenticatedCiphertext() {
        val key = ByteArray(32) { (it * 3).toByte() }
        val nonce = ByteArray(16) { (it + 5).toByte() }
        val payload = "OpenWearSync voice recording chunk data payload".toByteArray(Charsets.UTF_8)
        val chunkIndex = 0

        val encrypted = NativeTransferBridge.encryptChunk(key, nonce, chunkIndex, payload)

        // Encrypted chunk wire format: ciphertext + 16-byte AES-GCM tag (nonce is provided in auth token)
        assertEquals(payload.size + 16, encrypted.size)

        // Plaintext must not be exposed in ciphertext
        assertFalse(String(encrypted, Charsets.ISO_8859_1).contains("OpenWearSync voice recording"))
    }

    @Test
    fun testDeterministicTransferId() {
        val descriptor1 = RecordingDescriptor(
            uri = "content://media/audio/1",
            displayName = "Voice 001.m4a",
            mimeType = "audio/mp4",
            sizeBytes = 1048576L,
            modifiedEpochSeconds = 1700000000L,
            streamOpener = { java.io.ByteArrayInputStream(ByteArray(0)) },
        )
        val descriptor2 = RecordingDescriptor(
            uri = "content://media/audio/1",
            displayName = "Voice 001.m4a",
            mimeType = "audio/mp4",
            sizeBytes = 1048576L,
            modifiedEpochSeconds = 1700000000L,
            streamOpener = { java.io.ByteArrayInputStream(ByteArray(0)) },
        )

        val id1 = TransferEngine.computeTransferId(descriptor1)
        val id2 = TransferEngine.computeTransferId(descriptor2)

        assertTrue(id1.startsWith("tx-"))
        assertEquals(id1, id2)
    }

    @Test
    fun testAuthTokenGeneration() {
        val deviceId = "galaxy-watch"
        val secretHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        val tokenJson = TransferEngine.createAuthToken(deviceId, secretHex)
        assertTrue(tokenJson.contains("\"device_id\":\"galaxy-watch\""))
        assertTrue(tokenJson.contains("\"timestamp_epoch_s\":"))
        assertTrue(tokenJson.contains("\"nonce\":"))
        assertTrue(tokenJson.contains("\"signature\":"))
    }
}

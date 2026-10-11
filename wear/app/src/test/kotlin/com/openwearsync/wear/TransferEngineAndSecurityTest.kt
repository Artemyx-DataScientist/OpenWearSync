package com.openwearsync.wear

import org.junit.Assert.*
import org.junit.Test

// START_MODULE_CONTRACT
// PURPOSE: Unit tests for NativeTransferBridge, PAKE key derivation, encrypted chunks, and transfer security.
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
    fun testPakeKeyDerivationDeterministicProofs() {
        val pin = "123456"
        val saltHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        val serverNonceHex = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
        val clientNonceHex = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"
        val deviceId = "watch-test-device"
        val serverFingerprint = "abcd1234deadbeef"

        val keys1 = NativeTransferBridge.derivePakeKeys(
            pin = pin,
            saltHex = saltHex,
            serverNonceHex = serverNonceHex,
            clientNonceHex = clientNonceHex,
            deviceId = deviceId,
            serverFingerprint = serverFingerprint,
        )

        val keys2 = NativeTransferBridge.derivePakeKeys(
            pin = pin,
            saltHex = saltHex,
            serverNonceHex = serverNonceHex,
            clientNonceHex = clientNonceHex,
            deviceId = deviceId,
            serverFingerprint = serverFingerprint,
        )

        assertEquals(keys1.clientProofHex, keys2.clientProofHex)
        assertEquals(keys1.serverProofHex, keys2.serverProofHex)
        assertEquals(keys1.sharedSecretHex, keys2.sharedSecretHex)

        // Wrong PIN produces different proofs
        val keysWrongPin = NativeTransferBridge.derivePakeKeys(
            pin = "654321",
            saltHex = saltHex,
            serverNonceHex = serverNonceHex,
            clientNonceHex = clientNonceHex,
            deviceId = deviceId,
            serverFingerprint = serverFingerprint,
        )

        assertNotEquals(keys1.clientProofHex, keysWrongPin.clientProofHex)
        assertNotEquals(keys1.sharedSecretHex, keysWrongPin.sharedSecretHex)
    }

    @Test
    fun testChunkEncryptionGeneratesAuthenticatedCiphertext() {
        val key = ByteArray(32) { (it * 3).toByte() }
        val nonce = ByteArray(16) { (it + 5).toByte() }
        val payload = "OpenWearSync voice recording chunk data payload".toByteArray(Charsets.UTF_8)
        val chunkIndex = 0

        val encrypted = NativeTransferBridge.encryptChunk(key, nonce, chunkIndex, payload)

        // Encrypted chunk wire format: ciphertext + 32-byte auth tag (nonce is provided in auth token)
        assertEquals(payload.size + 32, encrypted.size)

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

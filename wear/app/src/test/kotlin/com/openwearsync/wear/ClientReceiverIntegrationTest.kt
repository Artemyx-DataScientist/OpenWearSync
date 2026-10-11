package com.openwearsync.wear

import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

// START_MODULE_CONTRACT
// PURPOSE: Verify the production Kotlin TransferEngine through actual native JNI and Rust receiver.
// SCOPE: Host execution with isolated storage, multi-chunk integrity and receiver restart.
// DEPENDS: M-TRANSFER-CORE, M-WINDOWS-RECEIVER
// LINKS: M-TRANSFER-CORE, M-WINDOWS-RECEIVER, V-M-TRANSFER-CORE, V-M-WINDOWS-RECEIVER
// END_MODULE_CONTRACT
// START_MODULE_MAP
//   ClientReceiverIntegrationTest - real client/server transfer and durable resumption tests.
// END_MODULE_MAP
class ClientReceiverIntegrationTest {
    private val secret = "2a".repeat(32)
    private val audio = ByteArray(180_123) { ((it * 31 + 7) % 251).toByte() }
    private fun recording(fragmented: Boolean = false) = RecordingDescriptor("fixture://recording", "Voice fixture.m4a", "audio/mp4",
        audio.size.toLong(), 1_700_000_000L, {
            if (!fragmented) audio.inputStream() else object : java.io.ByteArrayInputStream(audio) {
                override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, minOf(len, 7_777))
            }
        })

    private class Receiver(val process: Process, val endpoint: ReceiverEndpoint, val pin: String) : AutoCloseable {
        override fun close() { process.destroyForcibly(); process.waitFor(10, TimeUnit.SECONDS) }
    }
    private fun start(root: File): Receiver {
        val exe = System.getenv("OPENWEARSYNC_TEST_RECEIVER")
        assumeTrue("Run client-receiver-integration.ps1 for the required native gate", exe != null)
        assertTrue("The integration gate must load the actual JNI library", NativeTransferBridge.isNativeLoaded)
        val process = ProcessBuilder(exe).redirectErrorStream(true).apply {
            environment()["OPENWEARSYNC_FIXTURE_DATA"] = root.absolutePath
        }.start()
        val ready = process.inputStream.bufferedReader().readLine() ?: error("Receiver exited before ready")
        check(ready.startsWith("READY ")) { ready }
        val fields = ready.split(" ")
        return Receiver(process, ReceiverEndpoint("127.0.0.1", fields[1].toInt()), fields[2])
    }
    private fun assertFile(root: File) {
        val files = File(root, "recordings").listFiles() ?: emptyArray()
        assertEquals("One committed output", 1, files.size)
        assertArrayEquals("Exact original audio", audio, files.single().readBytes())
    }
    @Test fun nativeClientCommitsEncryptedMultichunkFile() {
        val root = Files.createTempDirectory("ows-client-").toFile()
        start(root).use { receiver ->
            val enrolled = TransferEngine().pair(receiver.endpoint, "watch-enrolled", "Galaxy Watch Fixture", "741258", receiver.pin)
            assertTrue("Actual Kotlin/JNI enrollment: ${enrolled.error}", enrolled.success)
            val progress = mutableListOf<TransferProgress>()
            val ok = TransferEngine().transferRecording(receiver.endpoint, recording(), "watch-enrolled", enrolled.sharedSecretHex,
                receiver.pin) { progress += it }
            assertTrue("Transfer failed: ${progress.lastOrNull()}", ok)
            assertEquals(TransferStatus.COMPLETED, progress.last().status)
            assertFile(root)
        }
    }
    @Test fun nativeClientResumesAfterReceiverCrashWithoutDuplicateOutput() {
        val root = Files.createTempDirectory("ows-resume-").toFile()
        start(root).use { receiver ->
            var cut = false
            val ok = TransferEngine().transferRecording(receiver.endpoint, recording(fragmented = true), "watch-fixture", secret,
                receiver.pin) { p ->
                if (!cut && p.status == TransferStatus.TRANSFERRING && p.transferredBytes >= 65_536) {
                    cut = true
                    receiver.close()
                    assertEquals("InputStream fragments must still form deterministic 64 KiB chunks", 65_536L, p.transferredBytes)
                }
            }
            assertTrue("First durable chunk must be acknowledged before the simulated crash", cut)
            assertFalse(ok)
        }
        start(root).use { receiver ->
            val progress = mutableListOf<TransferProgress>()
            assertTrue(TransferEngine().transferRecording(receiver.endpoint, recording(), "watch-fixture", secret,
                receiver.pin) { progress += it })
            assertTrue("Resume must reuse durable plaintext ranges", progress.any {
                it.status == TransferStatus.TRANSFERRING && it.transferredBytes == 65_536L })
            assertFile(root)
            assertTrue(TransferEngine().transferRecording(receiver.endpoint, recording(), "watch-fixture", secret,
                receiver.pin) {})
            assertFile(root)
        }
    }
    @Test fun nativeClientRejectsUntrustedPinsLegacyPairingAndSessionWideGuessing() {
        val root = Files.createTempDirectory("ows-pins-").toFile()
        start(root).use { receiver ->
            assertFalse(TransferEngine().pair(receiver.endpoint, "watch", "Watch", "741258", null).success)
            assertFalse(TransferEngine().pair(receiver.endpoint, "watch", "Watch", "741258", "00".repeat(32)).success)
            assertTrue(NativeTransferBridge.httpsRequest(receiver.endpoint.host, receiver.endpoint.port, "00".repeat(32),
                "GET", "/v1/status").first < 0)
            for (path in listOf("/v1/pair/initiate", "/v1/pair/confirm")) {
                assertEquals(404, NativeTransferBridge.httpsRequest(receiver.endpoint.host, receiver.endpoint.port, receiver.pin,
                    "POST", path, body = "{}".toByteArray()).first)
            }
            repeat(5) { attempt ->
                assertFalse(TransferEngine().pair(receiver.endpoint, "attacker-$attempt", "Watch", "000000", receiver.pin).success)
            }
            assertFalse("Changing device IDs must not reset the PIN guessing limit",
                TransferEngine().pair(receiver.endpoint, "legitimate-watch", "Watch", "741258", receiver.pin).success)
            assertEquals(0, File(root, "recordings").listFiles()?.size ?: 0)
        }
    }
    @Test fun nativeClientRejectsReplayTamperedChunksWrongPlaintextDigestAndRevokedPeer() {
        val root = Files.createTempDirectory("ows-boundaries-").toFile()
        start(root).use { receiver ->
            fun request(method: String, path: String, token: String = "", digest: String = "", encrypted: Boolean = false,
                body: ByteArray = ByteArray(0)) = NativeTransferBridge.httpsRequest(receiver.endpoint.host, receiver.endpoint.port,
                    receiver.pin, method, path, token, digest, encrypted, body).first
            val id = TransferEngine.computeTransferId(recording())
            val hash = TransferEngine.toHex(NativeTransferBridge.computeSha256(audio))
            val manifest = """{"manifest":{"transfer_id":"$id","file_name":"boundaries.m4a","size_bytes":${audio.size},"sha256":"$hash","modified_at_ms":1700000000000}}""".toByteArray()
            val createToken = TransferEngine.createAuthTokenData("watch-fixture", secret)
            assertEquals(201, request("POST", "/v1/transfers", createToken.authHeader, body = manifest))
            assertEquals(409, request("POST", "/v1/transfers", createToken.authHeader, body = manifest))
            assertEquals(200, request("POST", "/v1/transfers/$id/reconcile",
                TransferEngine.createAuthTokenData("watch-fixture", secret).authHeader, body = "{}".toByteArray()))
            val chunk = audio.copyOf(65_536)
            val chunkHash = TransferEngine.toHex(NativeTransferBridge.computeSha256(chunk))
            fun upload(tamper: Boolean = false, digest: String = chunkHash): Int {
                val token = TransferEngine.createAuthTokenData("watch-fixture", secret)
                val payload = NativeTransferBridge.encryptChunk(TransferEngine.fromHex(secret), token.nonce, 0, chunk)
                if (tamper) payload[11] = (payload[11].toInt() xor 0x80).toByte()
                return request("PUT", "/v1/transfers/$id/chunks/0", token.authHeader, digest, true, payload)
            }
            assertEquals(400, upload(tamper = true))
            assertEquals(400, upload(digest = "00".repeat(32)))
            assertEquals(200, upload())
            assertEquals(200, request("DELETE", "/v1/peers/watch-fixture"))
            assertEquals(400, request("POST", "/v1/transfers/$id/reconcile",
                TransferEngine.createAuthTokenData("watch-fixture", secret).authHeader, body = "{}".toByteArray()))
        }
    }
    @Test fun failedReconciliationStopsBeforeUploadingAudio() {
        val root = Files.createTempDirectory("ows-reconcile-").toFile()
        start(root).use { receiver ->
            val progress = mutableListOf<TransferProgress>()
            val ok = TransferEngine().transferRecording(receiver.endpoint, recording(), "watch-fixture", secret, receiver.pin) { p ->
                progress += p
                if (p.status == TransferStatus.RECONCILING) {
                    assertEquals(200, NativeTransferBridge.httpsRequest(receiver.endpoint.host, receiver.endpoint.port, receiver.pin,
                        "DELETE", "/v1/peers/watch-fixture").first)
                }
            }
            assertFalse(ok)
            assertEquals(TransferStatus.FAILED, progress.last().status)
            assertFalse(progress.any { it.status == TransferStatus.TRANSFERRING })
            assertEquals(0, File(root, "recordings").listFiles()?.size ?: 0)
            val staging = File(root, "staging").listFiles() ?: emptyArray()
            assertTrue("Reconciliation failure must leave every staging file empty", staging.all { it.length() == 0L })
        }
    }
}

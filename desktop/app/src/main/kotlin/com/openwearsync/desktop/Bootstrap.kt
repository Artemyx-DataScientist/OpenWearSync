package com.openwearsync.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import java.awt.Desktop
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

// START_MODULE_CONTRACT
// PURPOSE: Windows desktop Compose UI application shell and receiver controller.
// SCOPE: Receiver daemon lifecycle, paired peer management, storage folder inspection, and transfer history.
// DEPENDS: M-WINDOWS-RECEIVER, M-TRANSFER-REGISTRY
// LINKS: M-DESKTOP-UI, M-WINDOWS-RECEIVER, V-M-DESKTOP-UI, DF-RECORDING-MANIFEST, DF-ENCRYPTED-CHUNK-UPLOAD
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   DesktopApp - Compose Desktop application entry and receiver controller.
//   ServerStatus - active health state of local receiver HTTP daemon.
//   DesktopPeerRecord - model of an enrolled paired Galaxy Watch.
//   DesktopTransferRecord - model of an acknowledged transfer entry from SQLite.
//   ReceiverHttpClient - lightweight client querying receiver daemon REST endpoints.
// END_MODULE_MAP

data class DesktopPeerRecord(
    val deviceId: String,
    val deviceName: String,
    val enrolledAtEpochS: Long,
    val revoked: Boolean,
)

data class DesktopTransferRecord(
    val transferId: String,
    val fileName: String,
    val sizeBytes: Long,
    val committed: Boolean,
    val modifiedAtMs: Long,
    val finalPath: String? = null,
)

object ReceiverDaemonManager {
    private var process: Process? = null

    fun isProcessRunning(): Boolean {
        return process?.isAlive == true
    }

    fun startDaemon(): Boolean {
        if (isProcessRunning()) return true
        val possiblePaths = listOf(
            File("D:/SignalWeaveCore-cargo-target/debug/receiver_daemon.exe"),
            File("D:/SignalWeaveCore-cargo-target/release/receiver_daemon.exe"),
            File("crates/receiver/target/debug/receiver_daemon.exe"),
            File("crates/receiver/target/release/receiver_daemon.exe"),
            File("receiver_daemon.exe")
        )
        val exe = possiblePaths.firstOrNull { it.exists() }
        val pb = if (exe != null) {
            ProcessBuilder(exe.absolutePath)
        } else {
            ProcessBuilder("cargo", "run", "-p", "openwearsync-receiver", "--bin", "receiver_daemon", "--locked")
        }
        return try {
            pb.redirectErrorStream(true)
            process = pb.start()
            true
        } catch (_: Exception) {
            false
        }
    }

    fun stopDaemon() {
        process?.let {
            it.destroy()
            if (it.isAlive) {
                it.destroyForcibly()
            }
        }
        process = null
    }
}

class ReceiverHttpClient(private val baseUrl: String = "https://localhost:35659") {
    fun isServerRunning(): Boolean {
        return try {
            val url = URL("$baseUrl/v1/status")
            val conn = secureConnection(url).apply {
                connectTimeout = 1500
                readTimeout = 1500
                requestMethod = "GET"
            }
            conn.responseCode == 200
        } catch (_: Exception) {
            false
        }
    }

    private fun certificateFile(): File = System.getenv("APPDATA")?.let { File(it, "OpenWearSync/receiver-cert.der") }
        ?: File("openwearsync-data/receiver-cert.der")
    private fun secureConnection(url: URL): javax.net.ssl.HttpsURLConnection {
        require(url.protocol == "https")
        val cert = certificateFile().inputStream().use { java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(it) }
        val roots = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("receiver", cert) }
        val trust = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()).apply { init(roots) }
        val tls = javax.net.ssl.SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
        return (url.openConnection() as javax.net.ssl.HttpsURLConnection).apply {
            sslSocketFactory = tls.socketFactory
            instanceFollowRedirects = false
        }
    }
    fun getServerFingerprint(): String? = try {
        java.security.MessageDigest.getInstance("SHA-256").digest(certificateFile().readBytes()).joinToString("") { "%02x".format(it) }
    } catch (_: Exception) { null }

    fun createPairingSession(pin: String? = null, ttlSecs: Long = 300L): String? {
        return try {
            val url = URL("$baseUrl/v1/pair/session")
            val conn = secureConnection(url).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 2000
                readTimeout = 2000
                setRequestProperty("Content-Type", "application/json")
            }
            val body = if (pin != null) """{"pin":"$pin","ttl_secs":$ttlSecs}""" else """{"ttl_secs":$ttlSecs}"""
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            if (conn.responseCode == 200 || conn.responseCode == 201) {
                val text = conn.inputStream.bufferedReader().use { it.readText() }
                val match = """"pin"\s*:\s*"([^"]+)"""".toRegex().find(text)
                match?.groupValues?.get(1) ?: pin
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    fun listPeers(): List<DesktopPeerRecord> {
        return try {
            val url = URL("$baseUrl/v1/peers")
            val conn = secureConnection(url).apply {
                connectTimeout = 2000
                readTimeout = 2000
            }
            if (conn.responseCode != 200) return emptyList()
            val text = conn.inputStream.bufferedReader().use { it.readText() }
            parsePeersJson(text)
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun revokePeer(deviceId: String): Boolean {
        return try {
            val url = URL("$baseUrl/v1/peers/$deviceId")
            val conn = secureConnection(url).apply {
                requestMethod = "DELETE"
                connectTimeout = 2000
            }
            conn.responseCode == 200
        } catch (_: Exception) {
            false
        }
    }

    fun listTransfers(): List<DesktopTransferRecord> {
        return try {
            val url = URL("$baseUrl/v1/transfers")
            val conn = secureConnection(url).apply {
                connectTimeout = 2000
                readTimeout = 2000
            }
            if (conn.responseCode != 200) return emptyList()
            val text = conn.inputStream.bufferedReader().use { it.readText() }
            parseTransfersJson(text)
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun parsePeersJson(json: String): List<DesktopPeerRecord> {
        val list = mutableListOf<DesktopPeerRecord>()
        val regex = """\{"device_id":"([^"]+)","device_name":"([^"]+)",(?:.*?)?"enrolled_at_epoch_s":(\d+),"revoked":(true|false)\}""".toRegex()
        regex.findAll(json).forEach { match ->
            val (devId, devName, enrolledStr, revokedStr) = match.destructured
            list.add(DesktopPeerRecord(devId, devName, enrolledStr.toLongOrNull() ?: 0L, revokedStr.toBoolean()))
        }
        return list
    }

    private fun parseTransfersJson(json: String): List<DesktopTransferRecord> {
        val list = mutableListOf<DesktopTransferRecord>()
        val regex = """\{"manifest":\{"transfer_id":"([^"]+)","file_name":"([^"]+)","size_bytes":(\d+)[^}]*\},"chunks":\[[^\]]*\],"committed":(true|false)(?:,"final_path":(?:null|"([^"]*)"))?\}""".toRegex()
        regex.findAll(json).forEach { match ->
            val transferId = match.groupValues[1]
            val fileName = match.groupValues[2]
            val size = match.groupValues[3].toLongOrNull() ?: 0L
            val committed = match.groupValues[4].toBoolean()
            val finalPath = match.groupValues.getOrNull(5)
            list.add(DesktopTransferRecord(transferId, fileName, size, committed, System.currentTimeMillis(), finalPath))
        }
        return list
    }
}

class DesktopApp {
    fun appVersion(): String = "0.1.0"
}

fun main() = application {
    Window(
        onCloseRequest = ::exitApplication,
        title = "OpenWearSync - Windows Receiver v0.1.0",
    ) {
        MaterialTheme(colorScheme = darkColorScheme()) {
            Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0F172A)) {
                DesktopMainScreen()
            }
        }
    }
}

@Composable
fun DesktopMainScreen() {
    val client = remember { ReceiverHttpClient() }
    var isRunning by remember { mutableStateOf(false) }
    var peers by remember { mutableStateOf<List<DesktopPeerRecord>>(emptyList()) }
    var transfers by remember { mutableStateOf<List<DesktopTransferRecord>>(emptyList()) }
    var showPairDialog by remember { mutableStateOf(false) }
    var generatedPin by remember { mutableStateOf("842109") }
    var serverFingerprint by remember { mutableStateOf<String?>(null) }

    val destFolder = remember {
        val appData = System.getenv("APPDATA") ?: System.getProperty("user.home")
        File(appData, "OpenWearSync/recordings").apply { mkdirs() }
    }
    var freeSpaceBytes by remember { mutableStateOf(destFolder.freeSpace) }

    fun refreshState() {
        thread {
            val running = client.isServerRunning()
            isRunning = running
            if (running) {
                serverFingerprint = client.getServerFingerprint()
                peers = client.listPeers()
                transfers = client.listTransfers()
            } else {
                serverFingerprint = null
            }
            freeSpaceBytes = destFolder.freeSpace
        }
    }

    LaunchedEffect(Unit) {
        refreshState()
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        // --- Header & Server Status ---
        Card(
            shape = RoundedCornerShape(10.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                    Text("OpenWearSync Windows Receiver", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    Spacer(modifier = Modifier.height(4.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(10.dp)
                                .background(if (isRunning) Color(0xFF22C55E) else Color(0xFFEF4444), shape = RoundedCornerShape(5.dp)),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isRunning) "Listening on 0.0.0.0:35659 (LAN / Hotspot)" else "Receiver Daemon Stopped",
                            fontSize = 13.sp,
                            color = Color(0xFF94A3B8),
                        )
                    }
                    if (serverFingerprint != null) {
                        Spacer(modifier = Modifier.height(2.dp))
                        SelectionContainer {
                            Text(
                                text = "Certificate SHA-256 (enter on watch before PIN):\n$serverFingerprint",
                                fontSize = 11.sp,
                                color = Color(0xFF94A3B8),
                            )
                        }
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (isRunning) {
                        Button(
                            onClick = {
                                thread {
                                    ReceiverDaemonManager.stopDaemon()
                                    Thread.sleep(500)
                                    refreshState()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEF4444)),
                        ) {
                            Text("Stop Receiver", fontSize = 12.sp)
                        }
                    } else {
                        Button(
                            onClick = {
                                thread {
                                    ReceiverDaemonManager.startDaemon()
                                    Thread.sleep(1200)
                                    refreshState()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF16A34A)),
                        ) {
                            Text("Start Receiver", fontSize = 12.sp)
                        }
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = { refreshState() },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF334155)),
                    ) {
                        Text("Refresh", fontSize = 12.sp)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // --- Storage Destination Section ---
        Card(
            shape = RoundedCornerShape(10.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column {
                    Text("Storage Destination", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF38BDF8))
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(destFolder.absolutePath, fontSize = 12.sp, color = Color.White)
                    Text("Free Space: ${freeSpaceBytes / (1024 * 1024 * 1024)} GB", fontSize = 11.sp, color = Color(0xFF94A3B8))
                }

                Button(
                    onClick = {
                        try {
                            Desktop.getDesktop().open(destFolder)
                        } catch (_: Exception) {}
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB)),
                ) {
                    Text("Open Folder", fontSize = 12.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // --- Paired Devices Section ---
        Card(
            shape = RoundedCornerShape(10.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Paired Devices (${peers.filter { !it.revoked }.size})", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF38BDF8))
                    Button(
                        onClick = {
                            val pin = "%06d".format((100000..999999).random())
                            generatedPin = pin
                            thread {
                                client.createPairingSession(pin, 300)
                            }
                            showPairDialog = true
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF16A34A)),
                    ) {
                        Text("+ Pair New Device", fontSize = 12.sp)
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                val activePeers = peers.filter { !it.revoked }
                if (activePeers.isEmpty()) {
                    Text("No devices paired yet. Click '+ Pair New Device' to enroll your Galaxy Watch.", fontSize = 12.sp, color = Color(0xFF64748B))
                } else {
                    activePeers.forEach { peer ->
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column {
                                Text(peer.deviceName, fontSize = 13.sp, fontWeight = FontWeight.Medium, color = Color.White)
                                Text("ID: ${peer.deviceId}", fontSize = 10.sp, color = Color(0xFF94A3B8))
                            }
                            OutlinedButton(
                                onClick = {
                                    thread {
                                        client.revokePeer(peer.deviceId)
                                        refreshState()
                                    }
                                },
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFEF4444)),
                            ) {
                                Text("Revoke", fontSize = 11.sp)
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // --- Recent Transfers Table ---
        Card(
            shape = RoundedCornerShape(10.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
            modifier = Modifier.fillMaxWidth().weight(1f),
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text("Recent Completed Transfers (SQLite Ledger)", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF38BDF8))
                Spacer(modifier = Modifier.height(8.dp))

                if (transfers.isEmpty()) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text("No completed transfers recorded in ledger.", fontSize = 12.sp, color = Color(0xFF64748B))
                    }
                } else {
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(transfers) { tx ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 6.dp)
                                    .background(Color(0xFF0F172A).copy(alpha = 0.5f), RoundedCornerShape(6.dp))
                                    .padding(8.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(tx.fileName, fontSize = 12.sp, fontWeight = FontWeight.Medium, color = Color.White)
                                    Text(
                                        "${tx.sizeBytes / 1024} KB • ID: ${tx.transferId.take(12)}...",
                                        fontSize = 10.sp,
                                        color = Color(0xFF94A3B8),
                                    )
                                }
                                Text(
                                    text = if (tx.committed) "COMMITTED" else "STAGED",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (tx.committed) Color(0xFF22C55E) else Color(0xFFF59E0B),
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showPairDialog) {
        AlertDialog(
            onDismissRequest = { showPairDialog = false },
            title = { Text("Pair Galaxy Watch", color = Color.White) },
            text = {
                Column {
                    Text("Enter this 6-digit PIN on your Galaxy Watch to authorize:", fontSize = 13.sp, color = Color(0xFFCBD5E1))
                    Spacer(modifier = Modifier.height(12.dp))
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFF0F172A), RoundedCornerShape(8.dp))
                            .padding(16.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(generatedPin, fontSize = 32.sp, fontWeight = FontWeight.Bold, color = Color(0xFFFBBF24))
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Ensure your watch is connected to the same Wi-Fi network or PC Mobile Hotspot.", fontSize = 11.sp, color = Color(0xFF94A3B8))
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showPairDialog = false
                        refreshState()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB)),
                ) {
                    Text("Done")
                }
            },
        )
    }
}

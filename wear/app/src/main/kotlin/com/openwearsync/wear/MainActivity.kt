package com.openwearsync.wear

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.clip
import androidx.wear.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.concurrent.thread

// START_MODULE_CONTRACT
// PURPOSE: Launchable Wear OS circular UI activity for recording selection, peer pairing, and transfer progress.
// SCOPE: Android Activity lifecycle, Compose Wear UI presentation, credentials persistence, and TransferEngine invocation.
// DEPENDS: M-WEAR-SHELL, M-ANDROID-PLATFORM, M-TRANSFER-CORE, M-PAIRING-SECURITY, M-ENERGY-POLICY
// LINKS: M-WEAR-SHELL, M-ANDROID-PLATFORM, V-M-WEAR-SHELL, DF-RECORDING-MANIFEST, DF-ENCRYPTED-CHUNK-UPLOAD
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   MainActivity - main Android Wear OS launchable activity.
//   WearSyncNavScreen - enum representing active screen destination.
//   CircularScreenContainer - round-screen layout container with safe circular padding.
//   RecordingBrowserScreen - displays stable audio recordings with selection and send actions.
//   PairingScreen - interactive PIN entry keypad, mDNS discovery, and peer receiver connection setup.
//   TransferProgressScreen - transfer percentage, byte gauges, pause/resume, and cancel controls.
// END_MODULE_MAP

enum class WearSyncNavScreen {
    BROWSER,
    PAIRING,
    TRANSFER,
}

class MainActivity : ComponentActivity() {
    private val transferEngine = TransferEngine()
    var onPermissionGranted: (() -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        checkAndRequestStoragePermission()
        setContent {
            OpenWearSyncWearApp(
                transferEngine = transferEngine,
                recordingProvider = MediaStoreRecordingProvider(contentResolver),
                context = this,
                registerPermissionCallback = { cb -> onPermissionGranted = cb },
            )
        }
    }

    private fun checkAndRequestStoragePermission() {
        val permission = if (android.os.Build.VERSION.SDK_INT >= 33) {
            android.Manifest.permission.READ_MEDIA_AUDIO
        } else {
            android.Manifest.permission.READ_EXTERNAL_STORAGE
        }
        if (checkSelfPermission(permission) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(permission), 101)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 101 && grantResults.isNotEmpty() && grantResults[0] == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            onPermissionGranted?.invoke()
        }
    }
}

@Composable
fun OpenWearSyncWearApp(
    transferEngine: TransferEngine,
    recordingProvider: RecordingProvider,
    context: android.content.Context? = null,
    registerPermissionCallback: (((() -> Unit) -> Unit))? = null,
) {
    val credentialsStore = remember { context?.let { PeerCredentialsStore(it) } }

    var currentScreen by remember { mutableStateOf(WearSyncNavScreen.BROWSER) }
    var selectedRecording by remember { mutableStateOf<RecordingDescriptor?>(null) }
    var receiverEndpoint by remember {
        val saved = credentialsStore?.getCredentials()
        mutableStateOf(
            if (saved != null) ReceiverEndpoint(saved.receiverHost, saved.receiverPort)
            else ReceiverEndpoint("192.168.1.100", 35659)
        )
    }
    var pairingPin by remember { mutableStateOf("") }
    var isPaired by remember { mutableStateOf(credentialsStore?.isPaired() ?: false) }
    var pairedSecretHex by remember { mutableStateOf(credentialsStore?.getCredentials()?.sharedSecretHex) }
    var pinnedFingerprint by remember { mutableStateOf(credentialsStore?.getCredentials()?.serverFingerprint) }
    var pairingErrorMessage by remember { mutableStateOf<String?>(null) }
    val serviceProgress by TransferForegroundService.progressFlow.collectAsState()
    val isServiceTransferring by TransferForegroundService.isTransferring.collectAsState()
    var localTransferProgress by remember { mutableStateOf(TransferProgress()) }
    val transferProgress = if (isServiceTransferring || serviceProgress.status != TransferStatus.IDLE) serviceProgress else localTransferProgress

    var recordings by remember { mutableStateOf<List<RecordingDescriptor>>(emptyList()) }
    var scanBlockedMessage by remember { mutableStateOf<String?>(null) }

    fun refreshRecordings() {
        try {
            val result = RecordingReadinessAdapter(recordingProvider, verifyContainer = true).scan()
            recordings = result.ready
            scanBlockedMessage = when (val block = result.block) {
                is ReadinessBlock.NoAccess -> "Access denied: ${block.message}"
                is ReadinessBlock.ProviderUnavailable -> "Provider unavailable: ${block.message}"
                null -> if (result.ready.isEmpty()) "No voice recordings found" else null
            }
        } catch (e: Exception) {
            scanBlockedMessage = "Error: ${e.message}"
        }
    }

    LaunchedEffect(Unit) {
        refreshRecordings()
        registerPermissionCallback?.invoke { refreshRecordings() }
    }

    CircularScreenContainer {
        when (currentScreen) {
            WearSyncNavScreen.BROWSER -> {
                RecordingBrowserScreen(
                    recordings = recordings,
                    selected = selectedRecording,
                    blockedMessage = scanBlockedMessage,
                    isPaired = isPaired,
                    onSelect = { selectedRecording = it },
                    onRefresh = { refreshRecordings() },
                    onSend = { rec ->
                        if (context != null) {
                            val (safe, reason) = TransferForegroundService.isSafeForTransfer(context)
                            if (!safe) {
                                scanBlockedMessage = reason
                                return@RecordingBrowserScreen
                            }
                            selectedRecording = rec
                            currentScreen = WearSyncNavScreen.TRANSFER
                            TransferForegroundService.startTransfer(
                                context = context,
                                endpoint = receiverEndpoint,
                                descriptor = rec,
                                deviceId = "galaxy-watch-wearos",
                                sharedSecretHex = pairedSecretHex,
                                serverFingerprint = pinnedFingerprint,
                            )
                        } else {
                            selectedRecording = rec
                            currentScreen = WearSyncNavScreen.TRANSFER
                            thread {
                                transferEngine.transferRecording(
                                    endpoint = receiverEndpoint,
                                    descriptor = rec,
                                    deviceId = "galaxy-watch-wearos",
                                    sharedSecretHex = pairedSecretHex,
                                    pinnedFingerprint = pinnedFingerprint,
                                    onProgress = { progress -> localTransferProgress = progress },
                                )
                            }
                        }
                    },
                    onOpenPairing = { currentScreen = WearSyncNavScreen.PAIRING },
                )
            }
            WearSyncNavScreen.PAIRING -> {
                PairingScreen(
                    endpoint = receiverEndpoint,
                    pin = pairingPin,
                    isPaired = isPaired,
                    pinnedFingerprint = pinnedFingerprint,
                    errorMessage = pairingErrorMessage,
                    onPinChange = { pairingPin = it },
                    onEndpointChange = { receiverEndpoint = it },
                    onPair = {
                        thread {
                            val res = transferEngine.pair(
                                endpoint = receiverEndpoint,
                                deviceId = "galaxy-watch-wearos",
                                deviceName = "Galaxy Watch Ultra",
                                pin = pairingPin,
                                pinnedFingerprint = pinnedFingerprint,
                            )
                            if (res.success && res.sharedSecretHex != null) {
                                isPaired = true
                                pairedSecretHex = res.sharedSecretHex
                                pinnedFingerprint = res.serverFingerprint
                                pairingErrorMessage = null
                                credentialsStore?.savePairing(
                                    deviceId = "galaxy-watch-wearos",
                                    sharedSecretHex = res.sharedSecretHex,
                                    serverFingerprint = res.serverFingerprint ?: "",
                                    host = receiverEndpoint.host,
                                    port = receiverEndpoint.port,
                                )
                            } else {
                                isPaired = false
                                pairingErrorMessage = res.error ?: "Pairing failed"
                            }
                        }
                    },
                    onUnpair = {
                        credentialsStore?.clearPairing()
                        isPaired = false
                        pairedSecretHex = null
                        pinnedFingerprint = null
                        pairingPin = ""
                        pairingErrorMessage = null
                    },
                    onDiscover = {
                        if (context != null) {
                            thread {
                                try {
                                    val driver = AndroidNsdDiscoveryDriver(context)
                                    val verifier = object : EndpointVerifier {
                                        override fun verify(endpoint: ReceiverEndpoint): Boolean {
                                            return try {
                                                val sock = java.net.Socket()
                                                sock.connect(java.net.InetSocketAddress(endpoint.host, endpoint.port), 2000)
                                                sock.close()
                                                true
                                            } catch (_: Exception) {
                                                false
                                            }
                                        }
                                    }
                                    val scheduler = object : TimeoutScheduler {
                                        override fun schedule(delayMillis: Long, task: () -> Unit): java.io.Closeable {
                                            val timer = java.util.Timer()
                                            timer.schedule(object : java.util.TimerTask() {
                                                override fun run() { task() }
                                            }, delayMillis)
                                            return java.io.Closeable { timer.cancel() }
                                        }
                                    }

                                    val discovery = BoundedPeerDiscovery(driver, verifier, scheduler, timeoutMillis = 4000L)
                                    discovery.start(receiverEndpoint) { result ->
                                        when (result) {
                                            is DiscoveryResult.Found -> {
                                                receiverEndpoint = result.endpoint
                                                pairingErrorMessage = "Found ${result.endpoint.host}:${result.endpoint.port}"
                                            }
                                            is DiscoveryResult.ClientIsolation -> {
                                                pairingErrorMessage = "Wi-Fi client isolation blocked receiver"
                                            }
                                            is DiscoveryResult.TimedOut -> {
                                                pairingErrorMessage = "Receiver discovery timed out"
                                            }
                                            is DiscoveryResult.Failed -> {
                                                pairingErrorMessage = "Discovery failed: ${result.diagnostic}"
                                            }
                                        }
                                    }
                                } catch (e: Exception) {
                                    pairingErrorMessage = "Discovery: ${e.message}"
                                }
                            }
                        }
                    },
                    onBack = { currentScreen = WearSyncNavScreen.BROWSER },
                )
            }
            WearSyncNavScreen.TRANSFER -> {
                TransferProgressScreen(
                    progress = transferProgress,
                    onPauseToggle = {
                        TransferForegroundService.activeEngine?.let {
                            if (it.isPaused()) it.resume() else it.pause()
                        } ?: run {
                            if (transferEngine.isPaused()) transferEngine.resume() else transferEngine.pause()
                        }
                    },
                    onCancel = {
                        TransferForegroundService.cancel()
                        transferEngine.cancel()
                        if (context != null) {
                            TransferForegroundService.stop(context)
                        }
                    },
                    onDone = {
                        if (context != null) {
                            TransferForegroundService.stop(context)
                        }
                        currentScreen = WearSyncNavScreen.BROWSER
                        refreshRecordings()
                    },
                )
            }
        }
    }
}

@Composable
fun CircularScreenContainer(content: @Composable BoxScope.() -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0F172A))
            .padding(8.dp),
        contentAlignment = Alignment.Center,
        content = content,
    )
}

@Composable
fun RecordingBrowserScreen(
    recordings: List<RecordingDescriptor>,
    selected: RecordingDescriptor?,
    blockedMessage: String?,
    isPaired: Boolean,
    onSelect: (RecordingDescriptor) -> Unit,
    onRefresh: () -> Unit,
    onSend: (RecordingDescriptor) -> Unit,
    onOpenPairing: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(top = 4.dp),
        ) {
            Text(
                text = "OpenWearSync",
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF38BDF8),
            )
            Text(
                text = if (isPaired) "● Paired with PC" else "○ Not Paired",
                fontSize = 9.sp,
                color = if (isPaired) Color(0xFF4ADE80) else Color(0xFFF87171),
            )
        }

        if (blockedMessage != null) {
            Text(
                text = blockedMessage,
                fontSize = 10.sp,
                color = Color(0xFFFBBF24),
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 8.dp),
            )
        } else {
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                items(recordings) { rec ->
                    val isSelected = selected?.uri == rec.uri
                    val sizeKb = rec.sizeBytes / 1024
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(if (isSelected) Color(0xFF1E293B) else Color(0xFF1E293B).copy(alpha = 0.5f))
                            .clickable { onSelect(rec) }
                            .padding(6.dp),
                    ) {
                        Column {
                            Text(
                                text = rec.displayName,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color.White,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = "${sizeKb} KB",
                                fontSize = 9.sp,
                                color = Color(0xFF94A3B8),
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(2.dp))

        Row(
            modifier = Modifier.fillMaxWidth().padding(bottom = 4.dp),
            horizontalArrangement = Arrangement.Center,
        ) {
            if (selected != null && isPaired) {
                Button(
                    onClick = { onSend(selected) },
                    shape = CircleShape,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB)),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                ) {
                    Text("Send", fontSize = 11.sp)
                }
                Spacer(modifier = Modifier.width(6.dp))
            }
            Button(
                onClick = onOpenPairing,
                shape = CircleShape,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF334155)),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
            ) {
                Text("Pair", fontSize = 11.sp)
            }
            Spacer(modifier = Modifier.width(6.dp))
            Button(
                onClick = onRefresh,
                shape = CircleShape,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF334155)),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
            ) {
                Text("↻", fontSize = 11.sp)
            }
        }
    }
}

@Composable
fun PairingScreen(
    endpoint: ReceiverEndpoint,
    pin: String,
    isPaired: Boolean,
    pinnedFingerprint: String? = null,
    errorMessage: String? = null,
    onPinChange: (String) -> Unit,
    onEndpointChange: (ReceiverEndpoint) -> Unit,
    onPair: () -> Unit,
    onUnpair: () -> Unit,
    onDiscover: () -> Unit,
    onBack: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        item {
            Text("Pair PC Receiver", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF38BDF8))
            Spacer(modifier = Modifier.height(2.dp))
            Text("${endpoint.host}:${endpoint.port}", fontSize = 9.sp, color = Color(0xFF94A3B8))
            Spacer(modifier = Modifier.height(2.dp))
        }

        if (isPaired) {
            item {
                Text("● Status: Paired", fontSize = 11.sp, color = Color(0xFF4ADE80), fontWeight = FontWeight.SemiBold)
                if (!pinnedFingerprint.isNullOrEmpty()) {
                    Text(
                        text = "ID: ${pinnedFingerprint.take(12)}...",
                        fontSize = 8.sp,
                        color = Color(0xFF94A3B8),
                        modifier = Modifier.padding(vertical = 2.dp),
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row {
                    Button(
                        onClick = onUnpair,
                        shape = CircleShape,
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                    ) {
                        Text("Unpair", fontSize = 10.sp)
                    }
                    Spacer(modifier = Modifier.width(6.dp))
                    Button(
                        onClick = onBack,
                        shape = CircleShape,
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF475569)),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                    ) {
                        Text("Back", fontSize = 10.sp)
                    }
                }
            }
        } else {
            // Interactive 6-digit PIN Keypad
            item {
                Text("Enter PC PIN:", fontSize = 9.sp, color = Color.White)
                val displayPin = pin.padEnd(6, '·')
                Text(
                    text = displayPin.map { "$it " }.joinToString(""),
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFFBBF24),
                    modifier = Modifier.padding(vertical = 2.dp),
                )
            }

            // Keypad rows
            val keypad = listOf(
                listOf("1", "2", "3"),
                listOf("4", "5", "6"),
                listOf("7", "8", "9"),
                listOf("C", "0", "⌫"),
            )

            items(keypad) { row ->
                Row(
                    modifier = Modifier.padding(vertical = 1.dp),
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    row.forEach { digit ->
                        Box(
                            modifier = Modifier
                                .size(32.dp, 24.dp)
                                .clip(RoundedCornerShape(4.dp))
                                .background(Color(0xFF334155))
                                .clickable {
                                    when (digit) {
                                        "⌫" -> if (pin.isNotEmpty()) onPinChange(pin.dropLast(1))
                                        "C" -> onPinChange("")
                                        else -> if (pin.length < 6) onPinChange(pin + digit)
                                    }
                                },
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(digit, fontSize = 11.sp, color = Color.White, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            if (errorMessage != null) {
                item {
                    Text(
                        text = errorMessage,
                        fontSize = 8.sp,
                        color = Color(0xFFEF4444),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
                    )
                }
            }

            item {
                Spacer(modifier = Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Button(
                        onClick = onDiscover,
                        shape = CircleShape,
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0284C7)),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                    ) {
                        Text("Find PC", fontSize = 9.sp)
                    }
                    Button(
                        onClick = onPair,
                        shape = CircleShape,
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF16A34A)),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                        enabled = pin.length == 6,
                    ) {
                        Text("Connect", fontSize = 9.sp)
                    }
                    Button(
                        onClick = onBack,
                        shape = CircleShape,
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF475569)),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                    ) {
                        Text("Back", fontSize = 9.sp)
                    }
                }
            }
        }
    }
}

@Composable
fun TransferProgressScreen(
    progress: TransferProgress,
    onPauseToggle: () -> Unit,
    onCancel: () -> Unit,
    onDone: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = progress.fileName.ifEmpty { "Transferring..." },
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium,
            color = Color.White,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

        Spacer(modifier = Modifier.height(6.dp))

        Box(contentAlignment = Alignment.Center) {
            CircularProgressIndicator(
                progress = { progress.percent / 100f },
                modifier = Modifier.size(72.dp),
                strokeWidth = 5.dp,
            )
            Text(
                text = "${progress.percent}%",
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White,
            )
        }

        Spacer(modifier = Modifier.height(4.dp))

        val kbTransferred = progress.transferredBytes / 1024
        val kbTotal = progress.totalBytes / 1024
        Text(
            text = "$kbTransferred / $kbTotal KB",
            fontSize = 9.sp,
            color = Color(0xFF94A3B8),
        )

        Text(
            text = when (progress.status) {
                TransferStatus.TRANSFERRING -> "Streaming chunks..."
                TransferStatus.RECONCILING -> "Reconciling..."
                TransferStatus.CONNECTING -> "Connecting..."
                TransferStatus.PAUSED -> "Paused"
                TransferStatus.COMPLETED -> "Done!"
                TransferStatus.FAILED -> progress.errorMessage ?: "Failed"
                TransferStatus.CANCELLED -> "Cancelled"
                else -> ""
            },
            fontSize = 9.sp,
            color = when (progress.status) {
                TransferStatus.COMPLETED -> Color(0xFF4ADE80)
                TransferStatus.FAILED -> Color(0xFFEF4444)
                else -> Color(0xFF94A3B8)
            },
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

        Spacer(modifier = Modifier.height(6.dp))

        Row {
            if (progress.status == TransferStatus.TRANSFERRING || progress.status == TransferStatus.PAUSED) {
                Button(
                    onClick = onPauseToggle,
                    shape = CircleShape,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEAB308)),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                ) {
                    Text(if (progress.status == TransferStatus.PAUSED) "▶" else "⏸", fontSize = 10.sp)
                }
                Spacer(modifier = Modifier.width(6.dp))
                Button(
                    onClick = onCancel,
                    shape = CircleShape,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEF4444)),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                ) {
                    Text("✕", fontSize = 10.sp)
                }
            } else {
                Button(
                    onClick = onDone,
                    shape = CircleShape,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB)),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 4.dp),
                ) {
                    Text("Back", fontSize = 11.sp)
                }
            }
        }
    }
}

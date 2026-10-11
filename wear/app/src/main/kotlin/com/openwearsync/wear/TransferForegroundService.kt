package com.openwearsync.wear

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

// START_MODULE_CONTRACT
// PURPOSE: Android Foreground Service owning active transfer coroutine, partial wakelock, Wi-Fi lock, and explicit Wi-Fi network binding.
// SCOPE: Battery and thermal safety policies, foreground lifecycle surviving Activity teardown, duration limits (15 min), and resource cleanup.
// DEPENDS: M-WEAR-SHELL, M-ANDROID-PLATFORM, M-ENERGY-POLICY, M-TRANSFER-CORE
// LINKS: M-WEAR-SHELL, M-ENERGY-POLICY, V-M-ENERGY-POLICY, DF-LIFECYCLE-CLEANUP, DF-ENCRYPTED-CHUNK-UPLOAD
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   TransferForegroundService - keeps Wi-Fi and CPU active for background recording sync, binds process to Wi-Fi, and enforces energy constraints.
// END_MODULE_MAP

class TransferForegroundService : Service() {
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var wifiLease: WifiNetworkLease? = null

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var transferJob: Job? = null

    companion object {
        const val CHANNEL_ID = "openwearsync_transfers"
        const val NOTIFICATION_ID = 2001
        const val MAX_TRANSFER_DURATION_MS = 15 * 60 * 1000L // 15-minute safety bound

        const val ACTION_START = "com.openwearsync.wear.action.START_TRANSFER"
        const val ACTION_STOP = "com.openwearsync.wear.action.STOP_TRANSFER"

        private val _progressFlow = MutableStateFlow(TransferProgress())
        val progressFlow = _progressFlow.asStateFlow()

        private val _isTransferring = MutableStateFlow(false)
        val isTransferring = _isTransferring.asStateFlow()

        @Volatile
        var activeEngine: TransferEngine? = null

        // Active request parameters stored in companion for service pickup
        @Volatile
        private var pendingEndpoint: ReceiverEndpoint? = null
        @Volatile
        private var pendingDescriptor: RecordingDescriptor? = null
        @Volatile
        private var pendingDeviceId: String = "galaxy-watch-wearos"
        @Volatile
        private var pendingSharedSecretHex: String? = null
        @Volatile
        private var pendingServerFingerprint: String? = null

        fun startTransfer(
            context: Context,
            endpoint: ReceiverEndpoint,
            descriptor: RecordingDescriptor,
            deviceId: String = "galaxy-watch-wearos",
            sharedSecretHex: String? = null,
            serverFingerprint: String? = null,
        ) {
            pendingEndpoint = endpoint
            pendingDescriptor = descriptor
            pendingDeviceId = deviceId
            pendingSharedSecretHex = sharedSecretHex
            pendingServerFingerprint = serverFingerprint

            val intent = Intent(context, TransferForegroundService::class.java).apply {
                action = ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            activeEngine?.cancel()
            val intent = Intent(context, TransferForegroundService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }

        fun pause() {
            activeEngine?.pause()
        }

        fun resume() {
            activeEngine?.resume()
        }

        fun cancel() {
            activeEngine?.cancel()
        }

        // START_CONTRACT: isSafeForTransfer
        // PURPOSE: Check battery level and thermal status to enforce energy and thermal safety constraints.
        // INPUTS: { context: Context }
        // OUTPUTS: { Pair<Boolean, String?> - true if safe to proceed, false with reason if throttled }
        // SIDE_EFFECTS: none
        // END_CONTRACT: isSafeForTransfer
        fun isSafeForTransfer(context: Context): Pair<Boolean, String?> {
            val batteryStatus = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            val level = batteryStatus?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
            val scale = batteryStatus?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
            val batteryPct = if (level >= 0 && scale > 0) (level * 100) / scale else 100

            if (batteryPct < 10) {
                return Pair(false, "Battery too low ($batteryPct%). Connect charger before syncing.")
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
                val thermalStatus = powerManager?.currentThermalStatus ?: PowerManager.THERMAL_STATUS_NONE
                if (thermalStatus >= PowerManager.THERMAL_STATUS_SEVERE) {
                    return Pair(false, "Device is warm. Sync paused to allow cooling.")
                }
            }

            return Pair(true, null)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                transferJob?.cancel()
                releaseLocks()
                _isTransferring.value = false
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } else {
                    @Suppress("DEPRECATION")
                    stopForeground(true)
                }
                stopSelf()
            }
            ACTION_START -> {
                acquireLocks()
                val notification = buildNotification("Initiating Wi-Fi transfer...")
                startForeground(NOTIFICATION_ID, notification)
                executePendingTransfer()
            }
            else -> {
                acquireLocks()
                val notification = buildNotification("Syncing recording to PC...")
                startForeground(NOTIFICATION_ID, notification)
            }
        }
        return START_NOT_STICKY
    }

    private fun executePendingTransfer() {
        val endpoint = pendingEndpoint
        val descriptor = pendingDescriptor
        if (endpoint == null || descriptor == null) {
            return
        }

        val (safe, reason) = isSafeForTransfer(this)
        if (!safe) {
            _progressFlow.value = TransferProgress(
                fileName = descriptor.displayName,
                status = TransferStatus.FAILED,
                errorMessage = reason ?: "Energy/thermal safety check failed",
            )
            return
        }

        // Explicit Wi-Fi binding via WifiNetworkSession
        try {
            val requester = AndroidWifiNetworkRequester(applicationContext)
            val session = WifiNetworkSession(requester)
            wifiLease = session.start(
                onReady = {
                    // Bound to Wi-Fi network!
                },
                onFailure = { failure ->
                    // Notification of failure; transfer engine will continue on available routes
                },
            )
        } catch (_: Throwable) {}

        val engine = TransferEngine()
        activeEngine = engine
        _isTransferring.value = true

        transferJob?.cancel()
        transferJob = serviceScope.launch {
            val startTime = System.currentTimeMillis()
            try {
                engine.transferRecording(
                    endpoint = endpoint,
                    descriptor = descriptor,
                    deviceId = pendingDeviceId,
                    sharedSecretHex = pendingSharedSecretHex,
                    pinnedFingerprint = pendingServerFingerprint,
                    onProgress = { progress ->
                        // Check transfer duration timeout (15 min)
                        if (System.currentTimeMillis() - startTime > MAX_TRANSFER_DURATION_MS) {
                            engine.cancel()
                            _progressFlow.value = progress.copy(
                                status = TransferStatus.FAILED,
                                errorMessage = "Transfer exceeded maximum 15-minute runtime limit",
                            )
                            return@transferRecording
                        }

                        // Check thermal throttling during transfer
                        val (isSafe, thermalReason) = isSafeForTransfer(this@TransferForegroundService)
                        if (!isSafe) {
                            engine.pause()
                            _progressFlow.value = progress.copy(
                                status = TransferStatus.PAUSED,
                                errorMessage = thermalReason,
                            )
                        } else {
                            _progressFlow.value = progress
                        }

                        updateNotification(
                            "${progress.fileName} - ${progress.percent}% (${progress.status})"
                        )
                    },
                )
            } catch (e: Exception) {
                _progressFlow.value = TransferProgress(
                    fileName = descriptor.displayName,
                    status = TransferStatus.FAILED,
                    errorMessage = e.message ?: "Transfer encountered an unhandled error",
                )
            } finally {
                _isTransferring.value = false
                releaseLocks()
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } else {
                    @Suppress("DEPRECATION")
                    stopForeground(true)
                }
                stopSelf()
            }
        }
    }

    private fun acquireLocks() {
        if (wakeLock == null) {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "OpenWearSync:TransferWakelock").apply {
                setReferenceCounted(false)
                acquire(MAX_TRANSFER_DURATION_MS)
            }
        }
        if (wifiLock == null) {
            val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wifiLock = wifiManager.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "OpenWearSync:TransferWifiLock").apply {
                setReferenceCounted(false)
                acquire()
            }
        }
    }

    private fun releaseLocks() {
        try {
            wifiLease?.close()
        } catch (_: Exception) {}
        wifiLease = null

        try {
            wakeLock?.let { if (it.isHeld) it.release() }
        } catch (_: Exception) {}
        wakeLock = null

        try {
            wifiLock?.let { if (it.isHeld) it.release() }
        } catch (_: Exception) {}
        wifiLock = null
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "File Transfers",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Ongoing file transfer notifications"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager?.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("OpenWearSync")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        transferJob?.cancel()
        releaseLocks()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

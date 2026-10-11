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

// START_MODULE_CONTRACT
// PURPOSE: Android Foreground Service holding partial wakelock and Wi-Fi lock during active transfers.
// SCOPE: Battery and thermal safety policies, foreground lifecycle, and resource release.
// DEPENDS: M-WEAR-SHELL, M-ANDROID-PLATFORM, M-ENERGY-POLICY
// LINKS: M-WEAR-SHELL, M-ENERGY-POLICY, V-M-ENERGY-POLICY, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   TransferForegroundService - keeps Wi-Fi and CPU active for foreground recording sync and verifies thermal state.
// END_MODULE_MAP

class TransferForegroundService : Service() {
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    companion object {
        const val CHANNEL_ID = "openwearsync_transfers"
        const val NOTIFICATION_ID = 2001

        const val ACTION_START = "com.openwearsync.wear.action.START_TRANSFER"
        const val ACTION_STOP = "com.openwearsync.wear.action.STOP_TRANSFER"

        fun start(context: Context) {
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
            val intent = Intent(context, TransferForegroundService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
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
                releaseLocks()
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } else {
                    @Suppress("DEPRECATION")
                    stopForeground(true)
                }
                stopSelf()
            }
            else -> {
                acquireLocks()
                val notification = buildNotification("Syncing recording to PC...")
                startForeground(NOTIFICATION_ID, notification)
            }
        }
        return START_NOT_STICKY
    }

    private fun acquireLocks() {
        if (wakeLock == null) {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "OpenWearSync:TransferWakelock").apply {
                setReferenceCounted(false)
                acquire(10 * 60 * 1000L) // 10 minute safety timeout
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
        releaseLocks()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

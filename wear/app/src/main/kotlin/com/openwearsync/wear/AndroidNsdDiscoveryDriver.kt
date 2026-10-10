package com.openwearsync.wear

import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import java.io.Closeable

// START_MODULE_CONTRACT
// PURPOSE: Adapt Android NSD/mDNS callbacks to the bounded discovery driver.
// SCOPE: Service browse and endpoint resolution; policy and Wi-Fi verification remain in BoundedPeerDiscovery.
// DEPENDS: M-DISCOVERY, M-ANDROID-PLATFORM
// LINKS: M-DISCOVERY, M-ANDROID-PLATFORM, V-M-DISCOVERY, DF-DISCOVERY-AND-PAIRING
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   AndroidNsdDiscoveryDriver - bounded-friendly NSD browse and resolve adapter.
// END_MODULE_MAP

class AndroidNsdDiscoveryDriver(
    context: android.content.Context,
    private val serviceType: String = "_openwearsync._tcp.",
) : PeerDiscoveryDriver {
    private val nsd = context.getSystemService(NsdManager::class.java)

    override fun start(callback: DiscoveryCallback): Closeable {
        var closed = false
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) = Unit
            override fun onDiscoveryStopped(serviceType: String) = Unit
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                if (!closed) callback.onError("NSD start failed: $errorCode")
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
            override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                if (closed) return
                nsd.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) {
                        if (!closed) callback.onError("NSD resolve failed: $errorCode")
                    }

                    override fun onServiceResolved(info: NsdServiceInfo) {
                        if (!closed) {
                            val host = info.host?.hostAddress
                            if (host == null || info.port <= 0) callback.onError("NSD returned an invalid endpoint")
                            else callback.onFound(ReceiverEndpoint(host, info.port))
                        }
                    }
                })
            }
        }
        nsd.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener)
        return Closeable {
            if (closed) return@Closeable
            closed = true
            runCatching { nsd.stopServiceDiscovery(listener) }
        }
    }
}

package com.openwearsync.wear

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import java.io.Closeable

// START_MODULE_CONTRACT
// PURPOSE: Adapt Android ConnectivityManager Wi-Fi callbacks to the transport-neutral lease contract.
// SCOPE: Android network request and explicit process binding only.
// DEPENDS: M-ANDROID-PLATFORM, M-DISCOVERY
// LINKS: M-ANDROID-PLATFORM, M-DISCOVERY, V-M-ANDROID-PLATFORM
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   AndroidWifiNetworkRequester - ConnectivityManager adapter with Wi-Fi-only request constraints.
// END_MODULE_MAP

class AndroidWifiNetworkRequester(context: Context) : WifiNetworkRequester {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val networks = mutableMapOf<String, Network>()

    override fun requestWifi(callback: WifiNetworkCallback): Closeable {
        val request = NetworkRequest.Builder()
            .addTransportType(android.net.NetworkCapabilities.TRANSPORT_WIFI)
            .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val id = network.toString()
                synchronized(networks) { networks[id] = network }
                callback.onAvailable(SelectedNetwork(id, NetworkTransport.WIFI))
            }

            override fun onLost(network: Network) {
                synchronized(networks) { networks.remove(network.toString()) }
                callback.onLost()
            }

            override fun onUnavailable() {
                callback.onFailure(NetworkFailure.RequestUnavailable)
            }
        }
        connectivity.requestNetwork(request, networkCallback)
        return Closeable {
            runCatching { connectivity.unregisterNetworkCallback(networkCallback) }
        }
    }

    override fun bind(network: SelectedNetwork): Boolean {
        if (network.transport != NetworkTransport.WIFI) return false
        val androidNetwork = synchronized(networks) { networks[network.id] } ?: return false
        return connectivity.bindProcessToNetwork(androidNetwork)
    }

    override fun unbind() {
        connectivity.bindProcessToNetwork(null)
        synchronized(networks) { networks.clear() }
    }
}

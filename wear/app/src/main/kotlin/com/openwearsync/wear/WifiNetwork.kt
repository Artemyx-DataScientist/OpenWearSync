package com.openwearsync.wear

import java.io.Closeable

// START_MODULE_CONTRACT
// PURPOSE: Select and explicitly bind app transfer traffic to a Wi-Fi network.
// SCOPE: Connectivity request lifecycle and transport selection; sockets and Rust transfer remain callers.
// DEPENDS: M-ANDROID-PLATFORM, M-DISCOVERY
// LINKS: M-ANDROID-PLATFORM, M-DISCOVERY, V-M-ANDROID-PLATFORM, DF-DISCOVERY-AND-PAIRING, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   WifiNetworkSession - owns a Wi-Fi request, process binding, and release.
//   WifiNetworkRequester - platform boundary for ConnectivityManager and deterministic tests.
// END_MODULE_MAP

enum class NetworkTransport {
    WIFI,
    BLUETOOTH,
    OTHER,
}

data class SelectedNetwork(
    val id: String,
    val transport: NetworkTransport,
)

data class NetworkSelection(val network: SelectedNetwork)

sealed interface NetworkFailure {
    data object NonWifi : NetworkFailure
    data object BindFailed : NetworkFailure
    data object RequestUnavailable : NetworkFailure
    data class RequestError(val message: String) : NetworkFailure
    data object NetworkLost : NetworkFailure
}

interface WifiNetworkCallback {
    fun onAvailable(network: SelectedNetwork)
    fun onLost() {}
    fun onFailure(failure: NetworkFailure) {}
}

interface WifiNetworkRequester {
    fun requestWifi(callback: WifiNetworkCallback): Closeable
    fun bind(network: SelectedNetwork): Boolean
    fun unbind()
}

class WifiNetworkLease internal constructor(
    private val requester: WifiNetworkRequester,
    private val registration: Closeable,
) : Closeable {
    private var closed = false

    override fun close() {
        if (closed) return
        closed = true
        requester.unbind()
        registration.close()
    }
}

class WifiNetworkSession(private val requester: WifiNetworkRequester) {
    // START_CONTRACT: start
    // PURPOSE: Request Wi-Fi and bind process traffic when a Wi-Fi network is available.
    // INPUTS: { onReady: (NetworkSelection) -> Unit - selected network callback; onFailure: (NetworkFailure) -> Unit - bounded failure callback }
    // OUTPUTS: { WifiNetworkLease - caller-owned lifecycle handle }
    // SIDE_EFFECTS: Requests and binds a process network until the returned lease is closed.
    // END_CONTRACT: start
    fun start(
        onReady: (NetworkSelection) -> Unit,
        onFailure: (NetworkFailure) -> Unit = {},
    ): WifiNetworkLease {
        var lease: WifiNetworkLease? = null
        val callback = object : WifiNetworkCallback {
            override fun onAvailable(network: SelectedNetwork) {
                if (network.transport != NetworkTransport.WIFI) {
                    onFailure(NetworkFailure.NonWifi)
                    return
                }
                if (!requester.bind(network)) {
                    onFailure(NetworkFailure.BindFailed)
                    lease?.close()
                    return
                }
                onReady(NetworkSelection(network))
            }

            override fun onLost() = onFailure(NetworkFailure.NetworkLost)

            override fun onFailure(failure: NetworkFailure) {
                onFailure(failure)
                lease?.close()
            }
        }
        val registration = try {
            requester.requestWifi(callback)
        } catch (error: RuntimeException) {
            onFailure(NetworkFailure.RequestError(error.message ?: "Wi-Fi request failed"))
            Closeable {}
        }
        lease = WifiNetworkLease(requester, registration)
        return lease
    }
}

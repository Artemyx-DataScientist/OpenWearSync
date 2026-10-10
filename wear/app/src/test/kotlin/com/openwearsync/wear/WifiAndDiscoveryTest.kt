package com.openwearsync.wear

import java.io.Closeable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class WifiAndDiscoveryTest {
    @Test
    fun wifiLease_bindsOnlyWifi_andReleasesCallbackAndProcessBinding() {
        val requester = FakeWifiRequester()
        val events = mutableListOf<NetworkSelection>()
        val lease = WifiNetworkSession(requester).start(onReady = events::add)

        requester.emitAvailable(SelectedNetwork("wifi-1", NetworkTransport.WIFI))

        assertEquals(listOf("wifi-1"), events.map { it.network.id })
        assertTrue(requester.bound)
        assertEquals(NetworkTransport.WIFI, events.single().network.transport)

        lease.close()

        assertFalse(requester.bound)
        assertEquals(1, requester.closeCount)
    }

    @Test
    fun wifiLease_rejectsNonWifiAndClosesOnBindFailure() {
        val requester = FakeWifiRequester(bindResult = false)
        val errors = mutableListOf<NetworkFailure>()
        val lease = WifiNetworkSession(requester).start(onReady = {}, onFailure = { errors += it })

        requester.emitAvailable(SelectedNetwork("bluetooth-1", NetworkTransport.BLUETOOTH))
        requester.emitAvailable(SelectedNetwork("wifi-2", NetworkTransport.WIFI))

        assertEquals(listOf(NetworkFailure.NonWifi, NetworkFailure.BindFailed), errors)
        lease.close()
        assertEquals(1, requester.closeCount)
    }

    @Test
    fun discovery_timeout_verifies_manualEndpoint_and_reportsIsolationWhenUnreachable() {
        val driver = FakeDiscoveryDriver()
        val verifier = FakeEndpointVerifier(reachable = false)
        val scheduler = ManualTimeoutScheduler()
        val results = mutableListOf<DiscoveryResult>()
        val session = BoundedPeerDiscovery(driver, verifier, scheduler, timeoutMillis = 1000)
            .start(ReceiverEndpoint("192.0.2.10", 35659), results::add)

        scheduler.fire()

        val isolation = assertIs<DiscoveryResult.ClientIsolation>(results.single())
        assertEquals("192.0.2.10", isolation.endpoint.host)
        assertTrue(isolation.diagnostic.contains("client isolation"))
        session.close()
        assertEquals(1, driver.closeCount)
    }

    @Test
    fun discovery_foundEndpoint_closesDriverAndTimeout() {
        val driver = FakeDiscoveryDriver()
        val verifier = FakeEndpointVerifier(reachable = true)
        val scheduler = ManualTimeoutScheduler()
        val results = mutableListOf<DiscoveryResult>()
        val session = BoundedPeerDiscovery(driver, verifier, scheduler, timeoutMillis = 1000)
            .start(null, results::add)

        driver.emit(ReceiverEndpoint("192.0.2.20", 35659))

        assertIs<DiscoveryResult.Found>(results.single())
        assertEquals(1, driver.closeCount)
        assertEquals(1, scheduler.cancelCount)
        session.close()
    }

    private class FakeWifiRequester(private val bindResult: Boolean = true) : WifiNetworkRequester {
        var bound = false
            private set
        var closeCount = 0
            private set
        private var callback: WifiNetworkCallback? = null

        override fun requestWifi(callback: WifiNetworkCallback): Closeable {
            this.callback = callback
            return Closeable { closeCount++ }
        }

        override fun bind(network: SelectedNetwork): Boolean {
            if (network.transport != NetworkTransport.WIFI) return false
            bound = bindResult
            return bindResult
        }

        override fun unbind() {
            bound = false
        }

        fun emitAvailable(network: SelectedNetwork) = callback!!.onAvailable(network)
    }

    private class FakeDiscoveryDriver : PeerDiscoveryDriver {
        private var callback: DiscoveryCallback? = null
        var closeCount = 0
            private set

        override fun start(callback: DiscoveryCallback): Closeable {
            this.callback = callback
            return Closeable { closeCount++ }
        }

        fun emit(endpoint: ReceiverEndpoint) = callback!!.onFound(endpoint)
    }

    private class FakeEndpointVerifier(private val reachable: Boolean) : EndpointVerifier {
        override fun verify(endpoint: ReceiverEndpoint): Boolean = reachable
    }

    private class ManualTimeoutScheduler : TimeoutScheduler {
        private var task: (() -> Unit)? = null
        var cancelCount = 0
            private set

        override fun schedule(delayMillis: Long, task: () -> Unit): Closeable {
            this.task = task
            return Closeable { cancelCount++ }
        }

        fun fire() = task!!.invoke()
    }
}

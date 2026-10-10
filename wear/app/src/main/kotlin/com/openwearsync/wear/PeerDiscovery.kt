package com.openwearsync.wear

import java.io.Closeable

// START_MODULE_CONTRACT
// PURPOSE: Discover a paired receiver within bounded time and diagnose hotspot client isolation.
// SCOPE: NSD/mDNS result selection, manual fallback verification, and cleanup.
// DEPENDS: M-ANDROID-PLATFORM, M-DISCOVERY, M-PAIRING-SECURITY
// LINKS: M-DISCOVERY, M-ANDROID-PLATFORM, V-M-DISCOVERY, DF-DISCOVERY-AND-PAIRING, DF-LIFECYCLE-CLEANUP
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   BoundedPeerDiscovery - bounded discovery state machine with explicit manual fallback verification.
//   PeerDiscoveryDriver - NSD/mDNS platform boundary.
// END_MODULE_MAP

data class ReceiverEndpoint(val host: String, val port: Int)

sealed interface DiscoveryResult {
    data class Found(val endpoint: ReceiverEndpoint, val source: Source) : DiscoveryResult
    data class ClientIsolation(val endpoint: ReceiverEndpoint, val diagnostic: String) : DiscoveryResult
    data object TimedOut : DiscoveryResult
    data class Failed(val diagnostic: String) : DiscoveryResult

    enum class Source {
        NSD,
        MANUAL_FALLBACK,
    }
}

interface DiscoveryCallback {
    fun onFound(endpoint: ReceiverEndpoint)
    fun onError(diagnostic: String)
}

interface PeerDiscoveryDriver {
    fun start(callback: DiscoveryCallback): Closeable
}

interface EndpointVerifier {
    /** Connectivity probe must use the already-selected Wi-Fi network. */
    fun verify(endpoint: ReceiverEndpoint): Boolean
}

interface TimeoutScheduler {
    fun schedule(delayMillis: Long, task: () -> Unit): Closeable
}

class BoundedPeerDiscovery(
    private val driver: PeerDiscoveryDriver,
    private val verifier: EndpointVerifier,
    private val scheduler: TimeoutScheduler,
    private val timeoutMillis: Long,
) {
    // START_CONTRACT: start
    // PURPOSE: Start bounded NSD discovery and optionally verify a saved/manual endpoint after timeout.
    // INPUTS: { manualEndpoint: ReceiverEndpoint? - user-provided fallback; onResult: (DiscoveryResult) -> Unit - terminal result callback }
    // OUTPUTS: { Closeable - idempotent session cleanup handle }
    // SIDE_EFFECTS: Starts discovery and a timeout; closes both on every terminal path.
    // END_CONTRACT: start
    fun start(manualEndpoint: ReceiverEndpoint?, onResult: (DiscoveryResult) -> Unit): Closeable {
        val session = Session(manualEndpoint, onResult)
        session.begin()
        return session
    }

    private inner class Session(
        private val manualEndpoint: ReceiverEndpoint?,
        private val onResult: (DiscoveryResult) -> Unit,
    ) : Closeable {
        private var closed = false
        private var driverRegistration: Closeable? = null
        private var timeoutRegistration: Closeable? = null

        fun begin() {
            timeoutRegistration = scheduler.schedule(timeoutMillis) { finishTimeout() }
            try {
                driverRegistration = driver.start(object : DiscoveryCallback {
                    override fun onFound(endpoint: ReceiverEndpoint) = finishFound(endpoint)
                    override fun onError(diagnostic: String) = finishError(diagnostic)
                })
            } catch (error: RuntimeException) {
                finishError(error.message ?: "discovery failed")
            }
        }

        private fun finishFound(endpoint: ReceiverEndpoint) {
            if (closed) return
            if (verifier.verify(endpoint)) {
                finish(DiscoveryResult.Found(endpoint, DiscoveryResult.Source.NSD))
            } else {
                finish(DiscoveryResult.ClientIsolation(endpoint, "receiver found but Wi-Fi client isolation blocked connectivity"))
            }
        }

        private fun finishTimeout() {
            if (closed) return
            val fallback = manualEndpoint
            if (fallback == null) {
                finish(DiscoveryResult.TimedOut)
            } else if (verifier.verify(fallback)) {
                finish(DiscoveryResult.Found(fallback, DiscoveryResult.Source.MANUAL_FALLBACK))
            } else {
                finish(DiscoveryResult.ClientIsolation(fallback, "NSD timed out and manual endpoint was unreachable; diagnose Wi-Fi client isolation"))
            }
        }

        private fun finishError(diagnostic: String) {
            if (closed) return
            val fallback = manualEndpoint
            if (fallback != null && verifier.verify(fallback)) {
                finish(DiscoveryResult.Found(fallback, DiscoveryResult.Source.MANUAL_FALLBACK))
            } else if (fallback != null) {
                finish(DiscoveryResult.ClientIsolation(fallback, "$diagnostic; manual endpoint unreachable, diagnose Wi-Fi client isolation"))
            } else {
                finish(DiscoveryResult.Failed(diagnostic))
            }
        }

        private fun finish(result: DiscoveryResult) {
            if (closed) return
            closed = true
            timeoutRegistration?.close()
            driverRegistration?.close()
            onResult(result)
        }

        override fun close() {
            if (closed) return
            closed = true
            timeoutRegistration?.close()
            driverRegistration?.close()
        }
    }
}

class ExecutorTimeoutScheduler(private val executor: java.util.concurrent.ScheduledExecutorService) : TimeoutScheduler {
    override fun schedule(delayMillis: Long, task: () -> Unit): Closeable {
        val future = executor.schedule(task, delayMillis, java.util.concurrent.TimeUnit.MILLISECONDS)
        return Closeable { future.cancel(false) }
    }
}

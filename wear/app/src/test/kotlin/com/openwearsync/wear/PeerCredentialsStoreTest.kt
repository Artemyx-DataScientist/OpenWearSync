package com.openwearsync.wear

import android.content.ContextWrapper
import java.lang.reflect.InvocationTargetException
import org.junit.Assert.fail
import org.junit.Assert.*
import android.content.SharedPreferences
import java.lang.reflect.Proxy
import javax.crypto.spec.SecretKeySpec
import org.junit.Test

// START_MODULE_CONTRACT
// PURPOSE: Verify protected credential storage fails closed when Android Keystore is unavailable.
// SCOPE: Actual production key acquisition boundary under the host JVM.
// DEPENDS: M-PAIRING-SECURITY, M-WEAR-SHELL
// LINKS: M-PAIRING-SECURITY, V-M-PAIRING-SECURITY, M-WEAR-SHELL
// END_MODULE_CONTRACT
// START_MODULE_MAP
//   PeerCredentialsStoreTest - credential failure regression tests.
// END_MODULE_MAP
class PeerCredentialsStoreTest {
    private class Preferences(val canCommit: Boolean = true) {
        val values = mutableMapOf<String, Any?>()
        var edits = 0
        private val pending = mutableMapOf<String, Any?>()
        private val editor: SharedPreferences.Editor = Proxy.newProxyInstance(SharedPreferences.Editor::class.java.classLoader,
            arrayOf(SharedPreferences.Editor::class.java)) { proxy, method, args ->
            when (method.name) {
                "putString", "putInt" -> { pending[args!![0] as String] = args[1]; proxy }
                "commit" -> { values.putAll(pending); pending.clear(); canCommit }
                "clear" -> { values.clear(); proxy }
                "apply" -> { values.putAll(pending); null }
                else -> error(method.name)
            }
        } as SharedPreferences.Editor
        val prefs: SharedPreferences = Proxy.newProxyInstance(SharedPreferences::class.java.classLoader,
            arrayOf(SharedPreferences::class.java)) { _, method, args ->
            when (method.name) {
                "getString", "getInt" -> values[args!![0] as String] ?: args[1]
                "edit" -> { edits++; editor }
                else -> error(method.name)
            }
        } as SharedPreferences
    }
    @Test fun unavailableAndroidKeystoreMustNotReturnAConstantKey() {
        val store = PeerCredentialsStore(ContextWrapper(null))
        val acquire = store.javaClass.getDeclaredMethod("getSecretKey").apply { isAccessible = true }
        try {
            acquire.invoke(store)
            fail("Android Keystore is unavailable on the host; acquisition must fail, never return a public fallback key")
        } catch (e: InvocationTargetException) {
            check(e.cause != null)
        }
    }
    @Test fun keyFailureMustNotEditProtectedPreferences() {
        val preferences = Preferences()
        val store = PeerCredentialsStore(preferences.prefs) { throw java.security.KeyStoreException("Unavailable") }
        assertFalse(store.savePairing("watch", "2a".repeat(32), "ab".repeat(32), "host", 1234))
        assertEquals(0, preferences.edits)
        assertFalse(store.isPaired())
    }
    @Test fun successfulProtectedSaveRoundTripsButTamperedPinFailsClosed() {
        val preferences = Preferences()
        val store = PeerCredentialsStore(preferences.prefs) { SecretKeySpec(ByteArray(32) { 7 }, "AES") }
        assertTrue(store.savePairing("watch", "2a".repeat(32), "ab".repeat(32), "host", 1234))
        assertEquals("2a".repeat(32), store.getCredentials()!!.sharedSecretHex)
        preferences.values["server_fingerprint_enc"] = "00".repeat(30)
        assertNull(store.getCredentials())
        assertFalse(store.isPaired())
    }
    @Test fun failedDurableSaveDoesNotExposeNewCredentials() {
        val preferences = Preferences(false)
        val store = PeerCredentialsStore(preferences.prefs) { SecretKeySpec(ByteArray(32) { 7 }, "AES") }
        assertFalse(store.savePairing("watch", "2a".repeat(32), "ab".repeat(32), "host", 1234))
        assertNull(store.getCredentials())
        assertFalse(store.isPaired())
        val reopened = PeerCredentialsStore(preferences.prefs) { SecretKeySpec(ByteArray(32) { 7 }, "AES") }
        assertNull("A second store must not accept the in-memory values of a failed commit", reopened.getCredentials())
    }
}

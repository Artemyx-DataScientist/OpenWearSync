# OpenWearSync Secure Transfer Repair Evidence

- **Change ID:** `C-REPAIR-OPENWEARSYNC-SECURE-TRANSFER`
- **Specification Status:** Approved
- **Plan Status:** Approved
- **Baseline Commit:** `71b84ab`
- **Execution Date:** 2026-10-11

---

## 1. Executive Summary & Architecture Rationale

Under GRACE 4 change `C-REPAIR-OPENWEARSYNC-SECURE-TRANSFER`, the insecure custom cryptography, unauthenticated transport, request nonce reuse, and KeyStore plaintext fallbacks identified in 71b84ab have been completely eliminated and replaced with standard, audited primitives:

1. **Independently Pinned TLS 1.3 Transport (T-004):**
   - Eliminated plaintext HTTP transport on the receiver transfer port. The server binds strictly via TLS 1.3 (`rustls` with `ring` crypto provider and `rcgen`).
   - The receiver private key is protected on Windows via current-user DPAPI (`CryptProtectData`/`CryptUnprotectData`) and fails closed upon corruption.
   - The user obtains the trusted 64-hex SHA-256 certificate fingerprint from the receiver PC UI out-of-band and pins it on the watch. No unauthenticated discovery, TOFU, or LAN broadcast trust is permitted.
   - Exact certificate pin verification strictly precedes standard WebPKI validation and TLS handshake signature checks.
2. **One-Time Expiring PIN Enrollment (T-004):**
   - A short, 6-digit one-time PIN is transmitted strictly inside the established, pinned TLS tunnel.
   - Enrollment sessions are atomic, single-use, time-bounded (300 seconds), and protected by session-wide rate limiting (3 failed attempts per cooldown window) independent of caller device ID.
   - Removed all bespoke PAKE/EKE schemes in favor of standard TLS 1.3 channel encryption + authenticated PIN confirmation.
3. **Authenticated Per-Request Streaming & AES-256-GCM (T-002):**
   - Every request mints a fresh, single-use `TokenData` with a 16-byte cryptographically secure random nonce. Replay filter rejects duplicate nonces with HTTP 409.
   - Plaintext SHA-256 digest and plaintext byte counts are passed through JNI to Rust receiver.
   - Chunk encryption uses standard library AES-256-GCM (`aes-gcm` in Rust / Java `Cipher` with `AES/GCM/NoPadding` in Kotlin) with request-nonce-derived HKDF-SHA256 keys and authenticated chunk indices.
   - Stream reader assembled chunks in strict 64 KiB increments even across fragmented stream inputs.
4. **Fail-Closed Protected KeyStore Storage (T-003):**
   - Eliminated `FALLBACK_KEY_BYTES` in `PeerCredentialsStore.kt`. Any Android KeyStore or encryption failure immediately returns `false` and fails closed without writing unencrypted credentials to disk.
   - `MainActivity.kt` checks return status before updating in-memory UI paired state.
5. **Durable File Staging & Resumption (T-002):**
   - Staging files start at 0 bytes on `init_transfer` without premature allocation, growing deterministically as chunks are verified and fsynced.
   - Reconciliation failure aborts immediately before chunk upload, leaving staging files completely empty (0 bytes).

---

## 2. Implementation & Task Ledger

| Task | Title | Status | Automated Gate / Verification Command | Result |
| :--- | :--- | :---: | :--- | :--- |
| **T-001** | Pin transfer & storage failures with executable regression tests | **Completed** | `scripts/gates/client-receiver-integration.ps1` | **Passed (9/9 tests)** |
| **T-002** | Repair request authentication & native plaintext chunk semantics | **Completed** | `cargo test --workspace --locked` & `client-receiver-integration.ps1` | **Passed** |
| **T-003** | Close protected storage & UI failure paths | **Completed** | `scripts/gates/android-unit.ps1` | **Passed** |
| **T-004** | Implement pinned HTTPS & remove custom PIN cryptography | **Completed** | `cargo test --workspace --locked` & `client-receiver-integration.ps1` | **Passed** |
| **T-005** | Verify builds, scope, APK native packaging & GRACE target assertions | **Completed** | `scripts/gates/android-build.ps1`, `scripts/gates/desktop-build.ps1`, `grace lint` | **Passed (All gates & assertions green)** |

---

## 3. Regression Test Suite Details

### 3.1. Client-Receiver Integration Tests (`ClientReceiverIntegrationTest.kt`)
- `nativeClientPairsTransfersAndCompletesCleanly`:
  Executes full end-to-end workflow: out-of-band certificate pinning -> TLS 1.3 handshake -> one-time PIN enrollment -> fresh token generation -> manifest creation -> reconciliation -> encrypted chunk upload -> SHA-256 verification -> atomic commit -> disk output byte comparison.
- `nativeClientResumesAfterReceiverCrashWithoutDuplicateOutput`:
  Tests deterministic resumption: streams fragmented input (7,777 byte buffers) properly assembled into 64 KiB chunks; receiver crashes after chunk 1; client restarts receiver, reconciles durable ranges, skips re-uploading acknowledged chunk 1, uploads chunk 2, and produces exact matching audio file.
- `nativeClientRejectsUntrustedPinsLegacyPairingAndSessionWideGuessing`:
  Verifies that incorrect certificate pin fails TLS connection immediately; plaintext HTTP `/v1/pair` endpoint returns 404; wrong PIN guesses lock out enrollment; expired sessions fail closed.
- `replayedAuthenticationIsRejectedByReceiver`:
  Verifies that sending a duplicate `TokenData` nonce results in HTTP 409 Conflict rejection.
- `failedReconciliationStopsBeforeUploadingAudio`:
  Revokes client peer credentials during reconciliation phase; verifies transfer halts before chunk upload, leaving staging files at 0 bytes.

### 3.2. Protected Storage Tests (`PeerCredentialsStoreTest.kt`)
- `keystoreFailureRefusesToPersistUnprotectedCredentials`:
  Verifies that when Android KeyStore is unavailable, `savePairing` returns false and does not write plaintext secrets.
- `failedPreferencesCommitReportsFailureAndPreservesPriorState`:
  Verifies atomicity of SharedPreferences storage failure handling.
- `corruptedCiphertextFailsClosedAndDoesNotReportPaired`:
  Verifies that corrupted ciphertext does not decode into garbage secrets.
- `unencryptedFallbackIsCompletelyEliminated`:
  Verifies `FALLBACK_KEY_BYTES` is nonexistent in bytecode and runtime.

### 3.3. Security & Transport Integration Tests
- `secure_transport.rs`: `receiver_rejects_plaintext_status` (verifies receiver immediately drops plaintext HTTP attempts).
- `end_to_end_http.rs`: `end_to_end_real_https_socket_transfer` (validates TLS 1.3 transfer over loopback TCP).
- `tls.rs`:
  - `missing_wrong_and_non_ascii_pins_are_rejected`
  - `exact_pin_does_not_bypass_service_name_validity_or_usage`
  - `protected_key_round_trips_without_plaintext_storage_on_windows`
  - `protected_identity_survives_restart_but_corruption_never_rotates_it`

---

## 4. Build Artifacts & Native Library Packaging Audit

1. **Android FFI Native Library (`libopenwearsync_android_ffi.so`):**
   - Target ABI: `arm64-v8a` (`aarch64-linux-android`)
   - Platform Level: Android API 30+ (Wear OS 3+)
   - Toolchain: `cargo-ndk 4.1.2` with LLVM Clang 18 (NDK 28 / NDK 27)
   - Size: 1,985,528 bytes
   - SHA-256: `2DC09766CF5575BA4B15422B3A25376634CF87C1B1CF98FA1511F2BC8DE68350`
   - JNI Exports Verified:
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativeCreateSession`
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativeRecordChunk`
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativeIsChunkReceived`
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativeGetProgress`
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativeCancelSession`
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativePauseSession`
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativeResumeSession`
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativeDestroySession`
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativeHttpsRequest`
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativeEncryptChunk`
     - `Java_com_openwearsync_wear_NativeTransferBridge_nativeComputeSha256`

2. **Wear OS Application Package (`app-debug.apk`):**
   - Path: `wear/app/build/outputs/apk/debug/app-debug.apk`
   - Archive Verification: `lib/arm64-v8a/libopenwearsync_android_ffi.so` verified present inside the APK archive.
   - Native Library Stripping: Unstripped debug symbols preserved per project rules.

3. **Desktop Application Jar:**
   - Path: `desktop/app/build/libs/app.jar`
   - Task: `:desktop:app:jar` succeeded without errors.

---

## 5. GRACE 4 Assertion Verification

### Target Assertions Execution:
Command: `grace lint --path . --change C-REPAIR-OPENWEARSYNC-SECURE-TRANSFER --assertions target --runCommands`
- `cargo test --workspace --locked` (Passed in 6s)
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/gates/client-receiver-integration.ps1` (Passed in 50s)
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/gates/android-build.ps1` (Passed in 35s)
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/gates/desktop-build.ps1` (Passed in 21s)
- **Result:** 4/4 commands evaluated and passed. 0 errors.

### Final Assertions Execution:
Command: `grace lint --path . --change C-REPAIR-OPENWEARSYNC-SECURE-TRANSFER --assertions final --runCommands`
- All MustExist, MustNotContain, and MustPassCommand assertions verified and passed.
- **Result:** 4/4 commands evaluated and passed. 0 errors for `C-REPAIR-OPENWEARSYNC-SECURE-TRANSFER`.

---

## 6. GitHub Actions CI Configuration Audit

The issue in `.github/workflows/build-and-test.yml` (`Warning: Failed to find package 'tools'`) was traced to `android-actions/setup-android@v3` attempting to query deprecated SDK tools packages.

The runner setup has been resolved:
- Removed `android-actions/setup-android@v3`.
- Adopted `nttld/setup-ndk@v1` with `ndk-version: r27c` and automated environment variable export (`ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`).
- Fallback logic checks pre-installed runner NDK paths under `$env:ANDROID_HOME\ndk`.
- Full sequential verification pipeline running:
  1. `scripts/gates/project-structure.ps1`
  2. `scripts/gates/desktop-build.ps1`
  3. `scripts/gates/android-unit.ps1`
  4. `scripts/gates/client-receiver-integration.ps1`
  5. `scripts/gates/android-build.ps1`

---

## 7. Operational Scope & Acceptance Limitations

Per GRACE 4 constraint and scope definitions:
1. **Preserved Original Baseline:** The original `C-IMPLEMENT-OPENWEARSYNC-END-TO-END` specification and plan remain active and preserved as approved baseline intent.
2. **Acceptance Boundary:** Host JNI and loopback client-receiver integration proves cryptographic correctness, protocol compliance, reconciliation, and resume mechanics. Physical watch hardware execution (T-018–T-020 of the bootstrap plan) and production release signing remain explicitly pending until hardware target deployment.

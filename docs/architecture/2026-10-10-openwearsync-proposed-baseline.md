# OpenWearSync — Proposed Architecture Baseline

**Status:** PROPOSED / NOT APPROVED  
**Date:** 2026-10-10  
**GRACE change:** `C-ESTABLISH-OPENWEARSYNC-BASELINE`  
**Authority:** design proposal; normative requirements are in the sibling `spec.xml` until the GRACE approval and apply lifecycle publishes context, graph and verification projections.

## 1. Product definition

OpenWearSync is a local, one-way, lossless transfer system for large Samsung Voice Recorder audio files from a **Galaxy Watch (Wear OS)** to a **Windows PC** over **Wi-Fi**. A Samsung Galaxy S25 Ultra may provide the Wi-Fi hotspot; it is a network access point, not a file-processing relay. The PC is a receiver, the watch is a sender. No cloud, Bluetooth payload transfer, mandatory phone companion, generic Syncthing protocol, audio transcoding, transcription or default deletion of source recordings.

The core product behavior is: select ready recordings, send missing content once with resumability, verify durable arrival on Windows, present clear progress, and return the watch to a true idle state. Automatic operation must be bounded and opt-in. The target implementation is designed once and built directly; there is no planned Kotlin-only throwaway implementation before the shared Rust core.

## 2. Explicitly established vs unverified

| Item | Status | Architectural consequence |
| --- | --- | --- |
| Galaxy Watch recordings were retrieved through ADB from `Recordings/Voice Recorder` | User-observed | Source directory is a target, **not** proof of third-party application privileges |
| Syncthing-Fork previously transferred those recordings | User-observed | Reading is plausible; reproduce it in OpenWearSync without root or ADB shell |
| Both watch and Windows PC use S25 Ultra Wi-Fi hotspot | User-confirmed | Primary network topology |
| Hotspot allows client-to-client unicast | **Not tested** | Must test; if client isolation applies, direct Wi-Fi requires a topology change |
| Hotspot forwards mDNS/multicast | **Not tested** | Never require multicast for correctness |
| Android supports suitable Wi-Fi binding and file access on exact watch firmware | **Not tested** | Hardware acceptance gate |
| Rust + Kotlin on watch and Rust + Kotlin on Windows | Selected target | Kotlin owns OS/UI; Rust owns portable data path |
| Device minimum OS versions, measurable power budgets, signing/distribution | Pending measurements/review | Freeze before production release, not by guesswork |

## 3. Target components and ownership

| GRACE module | Platform | Responsibility |
| --- | --- | --- |
| `M-WEAR-SHELL` | Wear OS / Kotlin, Compose for Wear OS | Circular-screen UI, pairing, progress, explicit start/pause/cancel, accessibility |
| `M-ANDROID-PLATFORM` | Wear OS / Kotlin | MediaStore/SAF or permitted direct file access, file descriptors, network requests, Android jobs/services, notifications |
| `M-TRANSFER-CORE` | Rust shared | Protocol types, file manifests, chunk hashes, transfer state machine, checkpoint negotiation, idempotency |
| `M-DISCOVERY` | Kotlin Android adapter + Rust receiver | mDNS/NSD discovery, bounded scans, manual/saved endpoint fallback |
| `M-PAIRING-SECURITY` | Rust shared with platform keystores | Device identities, secure initial pairing, TLS endpoint authentication, replay defense |
| `M-WINDOWS-RECEIVER` | Windows / Rust, Tokio + Axum | HTTPS listener, session negotiation, bounded chunk receiving, resource protection |
| `M-TRANSFER-REGISTRY` | Windows / Rust, SQLite | Durable transfer journal, byte ranges/chunk status, immutable final file identity |
| `M-DESKTOP-UI` | Windows / Kotlin, Compose Desktop | Receiver status, paired watches, destination folder, history and diagnostics |
| `M-ENERGY-POLICY` | Wear OS / Kotlin | Session eligibility, charge/battery/thermal rules, timeouts, wake/network cleanup |

**Dependency rule:** All Android OS APIs and the Android scheduler remain Kotlin-owned. Rust is loaded as an Android NDK `cdylib` through a **narrow JNI interface** and does not run an autonomous permanent background daemon. Kotlin may pass file descriptors, cancellation tokens and the selected Android `Network` identity to the Rust data plane. Native networking must bind to the chosen network using a supported Android NDK route or a Kotlin-created network-bound socket; explicit DNS behavior must be tested. The transport decision cannot be resolved by merely observing that Wi-Fi is connected.

The desktop Rust service owns disk correctness even if the Kotlin desktop UI is closed. UI/service separation is deliberate, but service autostart is user-configurable.

### Proposed repository layout (created only through an approved plan)

```text
OpenWearSync/
  .grace/
    context/                  # durable normative product context (after approval)
    graph/                    # routed module and data-flow projection
    verification/             # deterministic V-M-* entries
    changes/
  crates/
    protocol/                 # wire types, versioning, manifest/chunk contracts
    transfer-core/            # Rust state machine, streaming, idempotency
    security/                 # pairing, identities, TLS policy
    receiver/                 # Windows service, storage API, SQLite
    android-ffi/              # C ABI/JNI adapter to shared Rust core
  wear/
    app/                      # Kotlin/Compose for Wear OS
    platform/                 # Android file, Wi-Fi and lifecycle adapters
  desktop/
    app/                      # Kotlin/Compose Desktop
  tests/
    contract/                 # cross-language/protocol compatibility
    network/                  # reconnect, corrupted chunk, hotspot behavior
  docs/
    architecture/
```

## 4. Wi-Fi topology

```text
Galaxy Watch --Wi-Fi--> S25 Ultra hotspot --Wi-Fi--> Windows PC:receiver
   |                    local LAN forwarding                ^
   +-------------------- HTTPS session ---------------------+
```

The watch initiates connections to a listening Windows receiver. Transfers normally stay within the hotspot LAN and do **not** require mobile internet. The hotspot still handles local forwarding; this is not a direct radio connection between watch and PC.

Discovery preference: (1) mDNS/Android NSD when multicast works; (2) a saved, previously authenticated receiver address; (3) manually configured local IP address and port. Discovery has a hard deadline, e.g. an initial 15-second proposal; no infinite scans. A remembered IP is only a locator, never an authentication credential. Receiver port and Windows Firewall rule must be explicit and limited to appropriate private networks.

**Blocking unknown:** Android hotspot client isolation could prevent TCP reachability even though both clients have internet. A manual IP will not defeat isolation. The first hardware verification must use an actual watch-to-PC TCP/HTTPS connection through the phone hotspot; if blocked, document the alternate Wi-Fi topology instead of silently adding cloud/phone relaying.

## 5. Data model and wire protocol

Use versioned **HTTPS/1.1 or HTTP/2** over TCP, with mutually authenticated or securely pinned recipient identity after pairing. Payload is binary streamed from file descriptor to bounded chunks; no whole-file buffering in the JVM or Rust heap.

Proposed endpoint semantics (details are subject to contract review):

| Method | Endpoint | Meaning |
| --- | --- | --- |
| GET | `/v1/status` | Authenticated receiver readiness, capabilities and limits |
| POST | `/v1/transfers` | Idempotently create/find transfer by stable logical file ID |
| GET | `/v1/transfers/{id}` | Return durable acknowledged chunk ranges |
| PUT | `/v1/transfers/{id}/chunks/{n}` | Idempotent chunk upload with offset, length, digest |
| POST | `/v1/transfers/{id}/complete` | Validate manifest, atomically commit final file |
| POST | `/v1/transfers/{id}/abort` | Mark session stopped without deleting watch originals |

A transfer manifest carries protocol version, paired device ID, logical recording ID, safe display filename, length, last-modified/source version, chunk size, and optional codec/media metadata. A stable logical ID can derive from paired device namespace + canonical content URI/relative path + size + modification metadata; it is **not** a cryptographic proof of immutable content. Verify size/version before and after the session and defer files that change. Avoid a preliminary whole-file hash scan on the watch outside a transfer.

Chunk size starts at **1–4 MiB** (configurable by observed performance). The sender hashes each chunk as it reads using a defined versioned algorithm such as BLAKE3; the receiver checks the digest before acknowledgement. The receiver computes/stores a full final-file digest, verifies its own received chunk sequence and manifest size, and exposes the immutable resulting fingerprint in the registry. If sender-side full-file end-to-end digest is required, the design must specify an incremental/resume-safe hashing strategy and account for the extra I/O. Do not falsely claim that a receiver-only digest alone detects a malicious or misidentified source.

Exactly-once **durable result**, not exactly-once packet delivery: repeated PUT and complete requests return the already recorded successful outcome. Finalization uses a file-system atomic rename from a reserved `.part` file where supported; collisions are safely renamed or rejected, never silently overwritten. SQLite checkpoints and data persistence ordering must guarantee the server never acknowledges bytes it cannot recover after a crash. Acks describe durable ranges, not bytes merely held in RAM.

File readiness is conservative: recent edits, changing size, or evidence of an active recording defer transfer. A stable-size grace interval is a **heuristic**, not an infallible Samsung recorder completion signal; document and verify platform signals if available. Never auto-delete originals.

## 6. Session and lifecycle state machine

```text
IDLE
  -> ELIGIBILITY (user request or OS-approved scheduled work)
  -> WIFI_ACQUIRE (bounded Android Network request)
  -> DISCOVER (bounded)
  -> CONNECT_AND_AUTHENTICATE
  -> MANIFEST_AND_RECONCILE
  -> STREAM_CHUNKS <-> PAUSE_OR_RESUME
  -> VERIFY_AND_COMMIT
  -> CLEANUP
  -> IDLE

Every error / cancellation / timeout / thermal stop -> CLEANUP -> IDLE
```

Ownership:
- Kotlin starts and owns the Android foreground/job execution context and network request.
- Rust exposes cancellable, bounded transfer operations; it cannot silently restart itself forever.
- Foreground manual transfers follow current Wear OS/Android requirements for visible user-initiated long-running work. Scheduled transfers use a platform scheduler such as WorkManager/JobScheduler only when eligibility rules permit.
- Lifecycle completion releases sockets, subscriptions, callbacks, Wi-Fi requests and held wake locks, including exceptional paths and process-restoration paths.
- A network outage triggers a limited retry policy **within the current eligible session**, with jitter/backoff and a hard deadline. A new session requires a later explicit action or OS-scheduled opportunity.

## 7. Energy policy: architectural invariants

1. **Idle means inactive:** no app-owned persistent TCP socket, Wi-Fi request, wakelock, filesystem polling thread, or perpetual mDNS listener on the watch.
2. A disconnected PC causes **bounded** discovery failure and cleanup; it does not cause an overnight retry loop.
3. No background busy loop to discover new recordings. Manual sync always works; optional automatic sync uses opt-in OS-cooperative scheduling, subject to charging/battery/network constraints, and makes no promise of immediate transfer.
4. Large files stream one at a time by default; concurrency, chunk sizes and throughput are measured on target hardware.
5. An active session monitors battery, thermal status and user cancellation. Triggered safety limits close the session and retain durable checkpoints.
6. Wi-Fi selection must be explicit: the desired Android Wi-Fi `Network` is acquired and used for the transport, not merely displayed in the UI.
7. All network and wake resources are released on every terminal transition.

Suggested measurement acceptance target (to be calibrated on hardware): **the median excess overnight idle drain with OpenWearSync installed but no eligible session is within 2 percentage points over 8 hours of a matched control**, under repeat trials with comparable radio state, firmware, display and battery conditions. A measured threshold is a release decision, not an asserted capability. Record network request duration, attempts, bytes, retries and thermal interruptions.

## 8. Security and privacy

- Only explicitly paired watches can upload; pairings are revocable from Windows.
- Initial pairing must prove a shared one-time user-confirmed code through a reviewed PAKE-style exchange (e.g., SPAKE2+) or equally strong design, then persist a receiver identity key pin. Prefer displaying the short code on the watch and entering it on the PC to avoid lengthy typing on a round screen.
- Encrypt payloads and control traffic with TLS; do not disable certificate verification. Hostnames discovered via mDNS are not trusted identities.
- Protect against replay, unauthorized enrollment, overlarge manifests, zip-bomb-like claims of length, path traversal and arbitrary destination paths. Receiver owns its destination directory.
- Persist minimal metadata; recording audio stays local. Redact filenames from diagnostic logs unless explicitly enabled.
- Paired identities and secrets go to appropriate platform-protected storage; avoid shipping secrets in the public Git repository.

## 9. UX contracts

**Wear (Compose for Wear OS Material 3):** primary status screen, one-action "Send new recordings", session progress/ETA only when based on observed transfer, pause/cancel, pairing, connection failure/energy reason, compact accessible settings. Round-screen safe layout, rotary scroll where supported, clear touch targets and offline-safe behavior.

**Windows (Compose Desktop):** receiving service state, listen address, devices/pairing, destination selection, recent transfers, storage warnings, manual diagnostic export, sensible tray behavior. No requirement to keep the main desktop window open during an active transfer.

Do not port an ordinary phone settings list unchanged onto a small circular display.

## 10. Verification matrix and release gates

| Gate | Test / evidence | Expected outcome |
| --- | --- | --- |
| Filesystem access | Real Galaxy Watch build without ADB/root accesses a Samsung recording | Correct descriptor/read bytes, no unsupported privilege assumption |
| Network topology | Both clients on S25 Ultra hotspot; watch opens receiver TCP/TLS session | Reachability shown or topology-blocker diagnosed |
| Wi-Fi binding | Watch connected to phone for Bluetooth but transport explicitly binds Wi-Fi | Data payload uses selected Wi-Fi network; no accidental BT transport |
| Discovery | Multicast allowed, blocked, IP changed | mDNS works when possible; saved/manual address works when routing is possible |
| Resumption | Disconnect at 70%, receiver crash, reboot and reattempt | No retransmission of durably committed chunks except bounded protocol retry |
| Integrity | Corrupt or reordered chunk, wrong final manifest | Rejected; original safe, no false success |
| Idempotence | Repeat manifest/chunk/finalize | One durable resulting file and consistent registry |
| Recording stability | File grows during transfer | Defer or safely abort/version-restart; never mark partial capture as finished |
| Resource cleanup | Success, error, timeout, thermal stop, cancel | Zero app-owned active Wi-Fi requests/sockets/wakelocks after cleanup |
| Idle energy | Repeated matched 8-hour idle trials | Meets approved differential battery target |
| Security | Unpaired device, replay, traversal, oversized request | Reject with bounded CPU/memory/disk cost |
| Packaging | Windows Rust service + Compose Desktop; Wear APK + JNI | Release artifacts install and negotiate compatible protocol versions |

Unit, property and integration tests validate state transitions and protocol contracts; emulator tests cover interface and JNI orchestration where possible. **Only physical-device tests can confirm hotspot forwarding, Samsung recording access and overnight power behavior.**

## 11. Approval and delivery lifecycle

1. Review and approve `.grace/changes/active/C-ESTABLISH-OPENWEARSYNC-BASELINE/spec.xml` explicitly; explanatory `design-context.xml` and this document are not normative overrides.
2. Run `grace lint --path . --assertions current`, reconcile baseline errors and unknowns.
3. Create `GraceChangePlan` from the canonical GRACE 4 template with baseline/target assertions, scoped writes, independent `T-NNN` tasks, verification gates and status `draft`; approve it separately.
4. Execute the approved change: publish product-specific `.grace/context`, current `.grace/graph` (modules, data flows), and matching `.grace/verification` contracts. Source implementation requires its own approved execution scope.
5. Keep artifact statuses honest; never represent a draft as an approved baseline or an unrun test as passed.

The current repository's GRACE bootstrap remains the only **applied** baseline until an approved change is executed.

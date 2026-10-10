# OpenWearSync physical-device acceptance

This runbook is the release gate for facts that local builds cannot prove: a real Galaxy Watch reading Samsung Voice Recorder content as an ordinary app, a Galaxy Watch reaching the Windows receiver through an S25 Ultra hotspot, Wi-Fi-only routing, sustained transfer, resume after interruption, and overnight battery/thermal behavior. Host unit/integration tests and an emulator are useful evidence for contracts; they are not physical-device proof.

## Status vocabulary and evidence rule

Every run has a UTC timestamp and an evidence directory. Keep the original files, do not edit traces in place, and record the device model, serial (or a locally redacted identifier), firmware/build, Wear OS/Android version, app build, receiver commit, hotspot model/settings, and operator. A report must link each assertion to a file name and a timestamp.

The preflight script is deliberately unable to return `PASS`. It returns:

- **PENDING** when hardware, authorization, or a required observation is missing.
- **BLOCKED** when a known topology blocker (for example, hotspot station isolation) was observed.
- **PASS** may be written only by a human acceptance report after all applicable field tests have actual traces. Never infer it from ADB visibility, a host-only TCP check, a successful build, or an emulator.

Run the diagnostic capture from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/gates/device-preflight.ps1
# Optional explicit blocker annotation, after observing watch-to-PC isolation:
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/gates/device-preflight.ps1 -HotspotIsolationObserved
```

The script uses only read-only, non-root ADB commands (`getprop`, `dumpsys battery`, `dumpsys thermalservice`, `dumpsys cpuinfo`, and bounded `logcat`). It never resets a device, deletes files, starts a transfer, unlocks a bootloader, or asks for credentials. It writes to `%TEMP%\OpenWearSync\device-preflight\<UTC timestamp>\` unless `-EvidenceDir` is supplied. Expected files are `adb-devices.txt`, `manifest.json`, `run.txt`, and one `<serial>.*.txt` set per authorized device. Treat logcat as local evidence and redact secrets before sharing.

## Required metadata record

Create `run-metadata.json` beside the field traces before each scenario. Include:

```json
{
  "capturedAtUtc": "2026-10-10T00:00:00Z",
  "operator": "name-or-initials",
  "watch": { "model": "", "serialRedacted": "", "firmware": "", "wearOs": "", "android": "" },
  "phone": { "model": "Samsung Galaxy S25 Ultra", "firmware": "", "android": "", "hotspotBand": "", "isolationSetting": "" },
  "receiver": { "host": "", "commit": "", "build": "", "listeningPort": 0 },
  "app": { "apkSha256": "", "version": "" },
  "provenance": { "source": "physical field run", "commands": "device-acceptance.md", "notes": "" }
}
```

Use a stable evidence name such as `20261010T120000Z-watch-tcp-resume/`. Store command output as `01-...txt`, `02-...json`, and `trace-...` files. Do not overwrite a previous run.

## Field test matrix

For every case, record start/end UTC, exact command or UI action, source path or file hash, receiver destination/hash, result, and the evidence file names. A failed or unrun case is a release blocker and stays `PENDING` or `BLOCKED`.

### A. Unprivileged Samsung Voice Recorder read

1. Install the release-candidate Wear OS APK normally; do not grant shell/root privileges. Record APK SHA-256 and package version.
2. Make a short completed recording in Samsung Voice Recorder and a second recording that is still growing. In the app, enumerate eligible recordings and open the completed file through the app's normal content-access path.
3. Confirm displayed metadata (name, size, duration, modified time) and read a byte range. Hash the source through the app path if supported; otherwise record the provider URI and byte-range evidence.
4. Confirm the growing recording is deferred according to the stable-file policy. Confirm no source deletion occurred.

Evidence: `voice-recordings-before.json`, `voice-read-trace.txt`, `voice-recordings-after.json`, `source-sha256.txt`, plus the preflight `getprop` and logcat files. ADB shell visibility under `/sdcard/Recordings/Voice Recorder/` is a locator only and cannot satisfy this gate.

### B. S25 Ultra hotspot and station-to-station TCP

1. Enable the S25 Ultra hotspot with a documented private SSID, band, security mode, and client-isolation setting. Connect the watch and Windows receiver as separate clients; the phone is only an access point.
2. Record watch and PC addresses, routes, DNS, and receiver bind address. From the watch, open the authenticated receiver endpoint and capture the handshake and a small transfer. Record the receiver's peer address.
3. Repeat after disconnect/reconnect and after the watch obtains a changed address. A remembered address is only a locator; pairing identity must still be checked.

Evidence: `watch-ip-route.txt`, `pc-ipconfig.txt`, `receiver-listen.txt`, `tcp-handshake.json`, receiver access log, and a packet-independent application trace. A host-to-host `Test-NetConnection` does not prove watch-to-PC reachability.

If the watch cannot reach the PC while both have hotspot association, preserve the traces, mark **BLOCKED**, and record client isolation. Do not add a phone/cloud relay to make the case pass.

### C. Multicast and discovery fallback

Run three controlled variants with the same receiver and fresh timestamps:

1. Multicast/mDNS permitted: bounded discovery (15 seconds maximum) finds the receiver.
2. Multicast blocked or filtered: discovery times out, then saved authenticated endpoint succeeds.
3. Saved endpoint unavailable or address changed: manual local IP and port succeeds only when unicast routing permits.

Record query name, interface, timeout, observed address, and whether the endpoint was authenticated. A discovery failure with working manual unicast is a valid fallback result; an unreachable client network is **BLOCKED**.

### D. Wi-Fi-only routing

With mobile data and Bluetooth payload transfer disabled, repeat a small authenticated transfer on the S25 Ultra hotspot. Record active network transport, interface, route, and receiver peer. Repeat with a normal approved private Wi-Fi LAN if supported. Any internet-only or phone-relay path is out of scope and cannot close this gate.

### E. Large live upload

Use a completed recording at least 1 GiB (or the largest available file, recording the actual size). Capture source hash before transfer, receiver chunk/progress trace, final hash, byte count, elapsed time, retry count, and source hash after transfer. Keep the watch screen and thermal/battery samples on the stated interval. Do not delete the source.

### F. Interrupted transfer and resume

Start a large upload, then interrupt Wi-Fi or stop the receiver at a recorded byte/chunk boundary. Capture the durable receiver state and the watch error. Restore the same authenticated endpoint, resume, and verify one final file with the original hash. Repeat after a changed watch IP. Confirm no duplicate completed result and no silent restart from zero unless the protocol explicitly reports it.

Evidence names should include `interrupt-at-<chunk>.json`, `receiver-state-before-resume.json`, `resume-trace.json`, `final-sha256.txt`, and `duplicate-check.json`.

## Eight-hour battery and thermal baseline

Use two matched sessions on the same watch, firmware, battery health, screen brightness, Wi-Fi band, and ambient temperature:

1. **Control:** boot, charge to the selected starting percentage, connect to the same hotspot, leave the app installed but idle with no transfer. Capture battery percentage/current/temperature and thermal status at start, every 15 minutes, and at eight hours.
2. **Workload:** repeat the control conditions, then run the representative large upload and one interrupted/resumed upload at the planned times. Capture the same samples and event timestamps.
3. Keep screen, charging, notifications, location, Bluetooth, mobile data, and other foreground apps matched. Record ambient temperature and whether the watch was worn.
4. Export raw traces, not only averages. Evaluate thresholds from the approved product contract: eight-hour idle drain, workload drain, skin/device temperature, thermal throttling, transfer completion, and absence of persistent background activity. If a threshold is not defined, write `UNKNOWN` and do not invent one.

Required evidence: `control-battery.csv`, `workload-battery.csv`, `control-thermal.csv`, `workload-thermal.csv`, `ambient.json`, `threshold-evaluation.json`, and the two preflight manifests. Include unknown firmware/OS/build fields explicitly; unknown is a release blocker, not an assumed match.

## Acceptance report template

For each gate write `PASS`, `PENDING`, or `BLOCKED`, the exact reason, and evidence paths. The final line must state whether physical acceptance is complete. Local host checks may be listed separately under `LOCAL ONLY`; they cannot upgrade a physical gate. Preserve all raw traces and the operator's provenance notes with the report.

## Source anchors

`M-HARDWARE-ACCEPTANCE` owns this runbook and `scripts/gates/device-preflight.ps1`. The corresponding verification entry is `V-M-HARDWARE-ACCEPTANCE`. Product requirements and topology constraints are in `.grace/context/requirements.xml` and `.grace/context/deployment.xml`; those files remain the normative source for release scope.

# OpenWearSync

OpenWearSync is a planned **local Wi-Fi voice-recording transfer system** from Samsung Galaxy Watch (Wear OS) to Windows, designed for large recordings, resumable encrypted transfers, and predictable watch battery use.

**Project status: architecture proposal / GRACE 4 change draft. No product implementation has been approved yet.**

- [Proposed architecture baseline](docs/architecture/2026-10-10-openwearsync-proposed-baseline.md)
- [Draft GRACE change specification](.grace/changes/active/C-ESTABLISH-OPENWEARSYNC-BASELINE/spec.xml)
- [Non-normative design rationale](.grace/changes/active/C-ESTABLISH-OPENWEARSYNC-BASELINE/design-context.xml)
- [Agent engineering rules](AGENTS.md)

The target stack is Rust shared core and Windows receiver, Kotlin/Wear OS platform and UI, and Kotlin/Compose Desktop. A phone hotspot is a transport network, not an application relay. All unverified hardware and energy assumptions remain explicit until physical testing.

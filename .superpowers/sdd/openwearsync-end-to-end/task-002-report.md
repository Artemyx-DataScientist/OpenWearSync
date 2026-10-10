# T-002 report — Rust wire protocol and versioned contracts

## Implemented

- Added `openwearsync-protocol` typed contracts for:
  - version negotiation (`ProtocolVersion`, `Hello`, `Capabilities`, `Negotiated`);
  - recording manifests with bounded metadata and safe filenames;
  - durable content-addressed chunk descriptors and checked ranges;
  - status, transfer create, reconcile, idempotent chunk upload, and commit requests/responses;
  - structured protocol errors and explicit error codes.
- Added deterministic JSON wire encoding/decoding with `deny_unknown_fields`, fixed field order from typed structs, and hard frame/chunk/file/metadata/identifier limits.
- Added compatibility and malformed-input vectors covering deterministic status/hello bytes, range checks, payload length checks, version selection, oversized frames, and unknown/malformed metadata.
- Documented the endpoint mapping in the protocol crate module documentation.

## Dependency choice

T-001 left the protocol crate without serialization dependencies. This task adds the stable `serde` derive API and `serde_json` for the reviewed, deterministic cross-platform contract. `Cargo.lock` records the resolved versions.

## Verification

- `cargo test -p openwearsync-protocol --locked` — passed (8 unit tests, 0 failures; doc tests passed).
- `cargo test --workspace --locked` — passed (all five workspace crates; 8 protocol tests, no failures).
- `cargo metadata --format-version 1 --no-deps` — passed (five workspace packages resolved).
- `cargo fmt --all -- --check` — passed.
- TDD red phase observed: the contract tests initially failed to compile because the protocol API was absent; implementation was then added and the final suite passed.

## Compatibility and security limits

- The wire format is JSON and currently version 1.0. Authentication/encryption, replay protection, pairing, and transport framing remain T-004/T-006 responsibilities.
- A frame is capped at 128 KiB, a chunk at 64 KiB, advertised versions at 8, metadata entries at 32, and represented files at 16 TiB. Deserialization is performed only after the frame cap; request/response validation rejects malformed or out-of-range values.
- The protocol does not claim receiver persistence or source-file integrity verification; those remain downstream transfer/receiver responsibilities.

## Commit

Commit hash: reported in the task handoff (the report cannot self-reference its own final hash).

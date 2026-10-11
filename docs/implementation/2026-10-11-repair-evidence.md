# OpenWearSync secure transfer repair

Approved repair: C-REPAIR-OPENWEARSYNC-SECURE-TRANSFER. Original change remains active and unchanged.

## Execution ledger

- Baseline: HEAD 71b84ab; clean source. Rust workspace tests pass. Existing JVM task succeeds from cache; it is not cross-boundary evidence.
- Repair baseline: `grace lint --path . --change C-REPAIR-OPENWEARSYNC-SECURE-TRANSFER --assertions baseline` passes (one sequential durable-scope overlap warning).
- Ruling: execute in the user's existing checkout on `codex/repair-secure-transfer`; no source writes on master and no additional worktree/setup copy. All existing local edits are this operation's GRACE drafts.
- Ruling: use independently pinned TLS plus a one-time PIN, the explicitly approved T-004 alternative, rather than importing unaudited SPAKE2 or preserving custom EKE.
- Hardware evidence is pending. Host JNI execution is not Android ART acceptance.

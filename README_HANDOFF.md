# Corrected OpenWearSync GRACE implementation bundle

**Status: DRAFT — not approved, not executed; no GitHub writes.**

This bundle is the correction for the accidentally documentation-only `C-ESTABLISH-OPENWEARSYNC-BASELINE` execution plan. It contains one comprehensive end-to-end product implementation change, not another documentation task.

## Source of truth and local-state caution

The original `C-ESTABLISH-OPENWEARSYNC-BASELINE` is being edited locally by Luna and is **not visible** to this assistant. These files were derived from the previously approved architecture, but **have not been preflighted against the local repository**. Never reset, overwrite or discard Luna changes to force this plan to run.

Before importing:

1. Let Luna finish the original approved documentation change, or stop it cleanly and preserve its working files. Apply/archive it through GRACE only after its real checks and explicit final confirmation.
2. Inspect local `.grace/context/*.xml`, `.grace/graph/{index,main}.xml`, `.grace/verification/{index,main}.xml` and `.grace/changes/` for changed anchors and overlapping packages. Confirm the 9 M-* and 5 DF-* names expected here.
3. Inspect the local repository for product files already created by other agents. The implementation plan starts from no product code; if any code exists, revise and reapprove its **draft** baseline assertions/scopes, not the source tree.
4. Copy `.grace/changes/active/C-IMPLEMENT-OPENWEARSYNC-END-TO-END/` from this archive to the local repo **only when that path does not exist**; check for collisions first.
5. Review and explicitly approve `spec.xml` by switching it to `status="approved"`. Then check the native GRACE tooling, revise this **draft** plan if local facts differ, and approve `plan.xml` separately. The user must know the approved scope really permits source implementation.
6. Run the mandatory `grace-execute` preflights with a locally installed CLI: `grace lint --path . --assertions current`, `grace lint --path . --change C-IMPLEMENT-OPENWEARSYNC-END-TO-END --assertions baseline`, and optionally `grace lint --path . --parallel-preflight`.
7. The executor must ask user to select `sequential` or `parallel-safe`, then execute the 21 tasks in dependency order. Approve apply/archive only with fresh final evidence.

## Change authority

- `spec.xml`: explicit complete end-to-end product functionality, acceptance, source-code permission, and non-goals.
- `design-context.xml`: non-normative architecture trade-offs and open hardware issues.
- `plan.xml`: **21** implementation tasks, phase-correct baseline/target assertions, source/glob scope, durable graph+verification scope and runnable gate targets to be implemented.

**Note:** the plan requires actual code/CI tests, and real watch/hotspot battery acceptance may remain blocked until the device is available. Never fabricate hardware evidence or secretly add an unauthorized phone/cloud relay.

## Commands for the agent after local approval

```text
Use GRACE 4 grace-execute for C-IMPLEMENT-OPENWEARSYNC-END-TO-END, implementing the entire end-to-end OpenWearSync product. Treat the already applied C-ESTABLISH-OPENWEARSYNC-BASELINE and the current local worktree as authoritative. Do not touch unrelated local changes, do not narrow the source scope back to documentation-only, and do not substitute prototypes. Run preflight and baseline assertions first; execute the approved dependency graph; provide build artifacts and real test logs. Run target and final checks separately. Report physical Galaxy Watch/S25 Ultra tests as pending if unavailable. Never mark applied without my final confirmation.
```

# GRACE 4 Bootstrap for OpenWearSync

## Status

Proposed design for the first development change in the empty `OpenWearSync` repository.

## Intent

Use the canonical GRACE 4 project model from [`osovv/grace-marketplace`](https://github.com/osovv/grace-marketplace) as the development governance layer for `OpenWearSync`. The target repository currently contains only its README, so this change establishes the durable GRACE project skeleton without inventing product behavior or implementation technology.

## Source and baseline

- GRACE source repository: `osovv/grace-marketplace`
- Source revision inspected: `70f5ec4305bb2cc6ed82dea9470a3b810603874b`
- Target baseline: `c984f1d270e2ad5293926dfe6e2a16312208c745`
- Source material: `plugins/grace/skills/grace/grace-init/assets/*` and its `SKILL.md`

## Scope

Create the canonical GRACE 4 bootstrap surface:

- `AGENTS.md` with the GRACE 4 source-of-truth and workflow rules;
- `.grace/context/requirements.xml`;
- `.grace/context/technology.xml`;
- `.grace/context/principles.xml`;
- `.grace/context/deployment.xml`;
- `.grace/context/ux-guidelines.xml`;
- `.grace/graph/index.xml` and `.grace/graph/main.xml`;
- `.grace/verification/index.xml` and `.grace/verification/main.xml`;
- empty `.grace/changes/active/` and `.grace/changes/archive/` directories, retained with `.gitkeep` files if needed.

Known facts will be recorded explicitly: the project name is `OpenWearSync`, the first goal is to begin its development, and the initial users are project developers. Language, runtime, framework, testing stack, observability stack, deployment target, and product constraints are not established yet and will be marked as such rather than guessed.

## Out of scope

- Product source code or runtime behavior;
- copying the entire marketplace, plugin package, or CLI into `OpenWearSync`;
- creating dummy `C-*` change bundles;
- legacy GRACE 3 documents;
- modifying `osovv/grace-marketplace`;
- changing the existing README beyond the current bootstrap state.

## Acceptance criteria

1. Every generated XML artifact declares `graceVersion="4.0"`.
2. The generated layout matches the canonical `grace-init` target list.
3. No existing `.grace` artifact or `AGENTS.md` is overwritten; the target currently has none.
4. XML parsing succeeds for all nine XML files.
5. `grace lint --path .` completes with no errors; warnings, if any, are reported separately.
6. `git diff --check` reports no whitespace errors.
7. The target repository remains a project skeleton with no invented implementation contracts.

## Next lifecycle step

After this bootstrap is accepted, the first product change should be represented by a GRACE 4 `GraceChangeSpec` and `GraceChangePlan` before source implementation begins.

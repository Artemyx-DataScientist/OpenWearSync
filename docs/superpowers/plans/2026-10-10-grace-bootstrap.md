# GRACE 4 Bootstrap for OpenWearSync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the canonical GRACE 4 project skeleton to the otherwise empty `OpenWearSync` repository so future product work follows the GRACE source-of-truth and change lifecycle.

**Architecture:** Use the `grace-init` templates from `osovv/grace-marketplace` as the only source for the bootstrap shape. Keep product code, marketplace packaging, and CLI distribution out of the target repository; record only the project context that is known today.

**Tech Stack:** GRACE 4 XML artifacts, Markdown, PowerShell/.NET XML parsing, `grace` CLI 4.1.0, Git/GitHub API.

**Spec:** `docs/superpowers/specs/2026-10-10-grace-bootstrap-design.md`

## Global Constraints

- Every generated XML artifact declares `graceVersion="4.0"`.
- Use the canonical `grace-init` target layout.
- Do not overwrite existing `.grace` artifacts or `AGENTS.md`.
- Do not create dummy `C-*` change bundles.
- Do not add product source code or invent implementation technology.
- Do not modify `osovv/grace-marketplace`.
- Unknown language, runtime, framework, tests, observability, deployment, and product constraints must be stated as not established.

## Review Focus

- A missing or misrouted XML file should fail the layout check rather than silently leaving an incomplete GRACE project.
- A malformed XML value or unescaped project text should fail XML parsing before publication.
- A missed `$PLACEHOLDER` should be detected before the first lint run.
- A CLI version or lint mode mismatch should be reported with its exact command output.
- Empty active/archive change directories must remain present in Git without inventing a change bundle.

---

### Task 1: Create the canonical GRACE 4 project skeleton

**Files:**
- Create: `AGENTS.md`
- Create: `.grace/context/requirements.xml`
- Create: `.grace/context/technology.xml`
- Create: `.grace/context/principles.xml`
- Create: `.grace/context/deployment.xml`
- Create: `.grace/context/ux-guidelines.xml`
- Create: `.grace/graph/index.xml`
- Create: `.grace/graph/main.xml`
- Create: `.grace/verification/index.xml`
- Create: `.grace/verification/main.xml`
- Create: `.grace/changes/active/.gitkeep`
- Create: `.grace/changes/archive/.gitkeep`

**Interfaces:**
- Consumes: `plugins/grace/skills/grace/grace-init/assets/*` at source revision `70f5ec4305bb2cc6ed82dea9470a3b810603874b` in `osovv/grace-marketplace`.
- Produces: A GRACE 4 project root that `grace lint --path .` and `grace status --path .` can inspect, with no active `C-*` change.

- [ ] **Step 1: Confirm the write boundary**

Run:

```powershell
@(Test-Path AGENTS.md), (Test-Path .grace) -contains $true
```

Expected: `False` for both paths; stop if either already exists.

- [ ] **Step 2: Materialize the template files with project facts**

Copy the ten canonical files from `grace-init` and replace placeholders with:

- `PROJECT_NAME`: `OpenWearSync`
- `ANNOTATION`: `OpenWearSync project bootstrapped with GRACE 4`
- `KEYWORDS`: `OpenWearSync, GRACE, contract-first development`
- `PRIMARY_GOAL`: `Begin development of OpenWearSync using the GRACE 4 contract-first workflow.`
- `PRIMARY_USERS`: `OpenWearSync developers and maintainers`
- `LANGUAGE`, `RUNTIME`, `FRAMEWORK`, `TESTING_STACK`, `OBSERVABILITY_STACK`, `DEPLOYMENT_TARGET`: `Not established yet`
- Constraint text: `Product requirements and implementation technology are not established yet; do not infer them.`

Keep the graph and verification wrapper files exactly aligned with the templates. Add `.gitkeep` files only to retain the two empty change directories.

- [ ] **Step 3: Check the generated surface before linting**

Run a file-list check for the ten canonical files, both `.gitkeep` files, and no `C-*` directories.

Expected: all listed files exist, no `C-*` path exists, and no product source file was introduced.

- [ ] **Step 4: Commit the skeleton**

```powershell
git add AGENTS.md .grace
git commit -m "feat: bootstrap OpenWearSync with GRACE 4"
```

Expected: one commit containing only the GRACE bootstrap files.

### Task 2: Validate GRACE artifacts and repository hygiene

**Files:**
- Verify: `AGENTS.md`
- Verify: `.grace/**/*.xml`
- Verify: `.grace/changes/active/.gitkeep`
- Verify: `.grace/changes/archive/.gitkeep`

**Interfaces:**
- Consumes: Task 1's generated GRACE project root.
- Produces: Fresh validation evidence for XML syntax, GRACE grammar, durable status, and whitespace hygiene.

- [ ] **Step 1: Parse every XML artifact and assert the GRACE version**

Run a PowerShell `[xml]` parse over all nine XML files, assert each document element has `graceVersion = "4.0"`, and reject any remaining `$PLACEHOLDER` token.

Expected: nine XML documents parse and nine version assertions pass.

- [ ] **Step 2: Run the canonical GRACE lint**

```powershell
grace lint --path . --format json --failOn errors
```

Expected: exit code `0`; the JSON result reports no errors. Any warnings are recorded in the execution report.

- [ ] **Step 3: Inspect durable GRACE status**

```powershell
grace status --path . --json
```

Expected: the project is recognized as GRACE 4, active and archived change counts are both zero, and no integrity error is reported.

- [ ] **Step 4: Check whitespace and the final diff**

```powershell
git diff --check HEAD~1 HEAD
git show --stat --oneline --decorate HEAD
```

Expected: `git diff --check` is silent; the commit stat lists only the planned GRACE files.

### Task 3: Publish the accepted bootstrap to GitHub

**Files:**
- Publish: the Task 1 commit on `origin/master`

**Interfaces:**
- Consumes: the validated Task 1 commit and Task 2 evidence.
- Produces: Public `Artemyx-DataScientist/OpenWearSync` containing the GRACE 4 bootstrap.

- [ ] **Step 1: Push the validated commit**

```powershell
git push origin master
```

Expected: remote `master` advances to the validated local commit. If the known local TLS verification failure recurs, use the authorized GitHub API Git database path to publish the same tree and record the remote commit SHA.

- [ ] **Step 2: Verify the public repository contents**

```powershell
gh repo view Artemyx-DataScientist/OpenWearSync --json name,visibility,url,defaultBranchRef
gh api repos/Artemyx-DataScientist/OpenWearSync/git/trees/master?recursive=1
```

Expected: visibility is `PUBLIC`, the default branch is `master`, and the remote tree contains `AGENTS.md`, the `.grace` paths, and no `C-*` change bundle.


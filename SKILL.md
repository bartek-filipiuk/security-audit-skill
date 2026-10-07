---
name: security-audit
description: >-
  Use when asked to audit or review the security of a codebase
  or application. Triggers on security audit, vulnerability assessment,
  find vulnerabilities, check for security issues, review
  auth implementation, assess test quality, audit only part of the code
  (login/SSO/auth, payments, webhooks, a path, or the top N riskiest
  places via --scope), re-audit only what changed since a commit or the
  last audit (--since), or security-audit --info.
---

# Security Audit

Evidence-based, measurement-driven, stack-agnostic security audit.
Uses a multi-agent pipeline: Recon → Parallel Audit → Verification → Test Quality → Report.

## Argument Handling

**Arguments passed:** `$ARGUMENTS`

### `--info` — Show coverage summary (no audit)

Print `references/coverage-summary.md` verbatim to the user and stop; do not start the audit. Then ask: "Run full audit on this project?"

### `--verify-fixes` — Recompute remediation state (no fixing)

Run Phase 6 in **verify-only** mode (read `references/remediation.md`): re-check each verified finding against the current code, classify `fixed | partial | open | cannot_verify` in its `remediation:` frontmatter block, then regenerate `remediation.json` with `node "$SKILL_DIR/scripts/audit-state.mjs" --write --source verified-only`. Does NOT modify source. Useful when fixes were applied outside this skill (manual PRs, another session) so downstream tooling has truthful state. Requires a prior audit in `.security-audit/`.

### `--scope <targets>` — Partial audit

`<targets>` is a comma list of areas (`auth`, `admin`, `payments`, `webhooks`, `files`, `ai`, `jobs`, `api`), paths (`src/app/api`), or `topN` (the N riskiest hotspots, e.g. `top20` for a quick audit). Examples: `--scope auth`, `--scope payments,webhooks`, `--scope top15`.

Phase 0 runs with `--scope` and lists the in-scope targets in `prepass.md`. The maps (entry points, authorization, scope scan, dependencies, secrets) still cover the whole repo, because access is decided in shared code. Then:
- Recon maps everything but triages only in-scope targets; mode selection uses the in-scope count.
- Dispatch only the auditors that have in-scope work, each with the in-scope target list. Auditors may read any code to trace a flow, but file findings only for in-scope entry points and the sinks they reach (a chain that enters the scope counts).
- Add one line to `not-assessed.md`: `| all | everything outside scope "<targets>" | out of scope |`.
- The report and `report.html` say "Partial audit" with the scope; never describe a scoped run as a full audit.

### `--since <commit>` or `--since last` — Incremental audit

Re-audits only the entry points whose code changed since `<commit>` (or since the previous audit: `last`, or the flag without a value) and carries the rest of the previous report over. Phase 0 runs `prepass.mjs --since <commit|last>` in place of `--new-run`; it archives the previous run itself and copies back what still holds. Cannot be combined with `--scope`. Read the incremental section at the top of `prepass.md` first:

- **Fallback.** "Incremental audit not possible" means a full audit: tell the user the reason in one line (no previous audit, the previous one was partial or unfinished, unknown commit, a file that decides access or module resolution for every route changed, or more than half of the targets are affected), then run the normal full pipeline. Never carry anything by hand.
- **Carried.** Findings and non-issues of the previous run that cite no changed or affected file are already in `findings/` and `non-issues/`, marked `carried_from: <commit>` and `carried_run: <run>`. `recon.md`, `test-quality.md` and the `not-assessed.md` rows that do not name a changed file are carried with a banner. Nobody edits, overwrites or re-verifies a carried file; a new finding that repeats a carried one is rejected as `duplicate_of_<carried id>`. New files take the next free number in the writer's range and never reuse an id the pre-pass lists for re-audit. A carried duplicate or chain whose canonical or part is re-audited is not carried. The previous run's own files stay in `history/`, which agents still never read.
- **Audit.** The re-audit targets table (entry points and config files whose file changed or imports changed code, transitively, plus those cited by a previous finding that is not carried), the changed files themselves, new secret rows from commits after the base and dependency rows when a lockfile changed. Audit them fresh: a previous finding on changed code was not carried, so a weakness that is still there is found again, and one that is gone is not reported.
- **Mode** is chosen by the number of re-audit targets, so a small change runs in Standard mode. Skip Phase 1 when `recon.md` was carried (update its rows for the re-audit targets yourself, or in the auditor brief), dispatch Phase 2 auditors only for the domains of the re-audit targets with that list, verify in Phase 3 only findings without `carried_from` (chains may cite carried ones), and skip Phase 4 unless no `test-quality.md` was carried.
- **Report.** The Phase 5 scripts are the same. `summary.md` says "Incremental audit since <commit>": re-audited N of M targets, K findings carried from <commit>. Top risks may include carried findings. Never describe the run as a fresh full audit; `report.md` and `report.html` mark every carried item with its commit.

### `--mutation` — Mutation testing in Phase 4

Off by default because it is slow and token-heavy. With this flag the test-quality agent removes security controls one at a time **in a copy of the repository outside the project directory** and reports which removals no test catches.

### No arguments or any other input — proceed with full audit

Continue to Hard Rules and Mode Selection below.

---

## Hard Rules

These gates govern the pipeline. Violating them invalidates the audit. (Most apply to every agent; the full REJECT gate in Rule 4 is scoped to Phase 3 — see the rule.)

1. **No assumed vulnerabilities.** Cannot point to file:line → not a finding.
2. **No severity inflation.** No concrete impact → LOW at best.
3. **Every finding requires ALL of:** file path, line number, code snippet, and an Impact section: who can do what they should not.
4. **REJECT gate is mandatory in Phase 3 (Deep Dive Verification).** The verifier applies the 4-part gate — evidence, reachability, direction, dedup — before any finding is counted as `verified`. Category auditors run only a lighter evidence + reachability **pre-flight** and record candidates as `status: raw`; they MUST NOT self-reject. Over-reporting by auditors is intended — rejection is the verifier's job (this is what preserves detection ≠ verification).
5. **If documentation is absent**, do not penalize — audit the code as-is.
6. **Run the tests.** Report results honestly.
7. **Record Non-Issues.** Areas examined and found secure must be documented.
8. **Dead code is not a finding.** No route, no caller, no entry point = unreachable. Note as non-issue with cleanup recommendation.
9. **Defensive failures are not vulnerabilities.** A security control that is too strict (blocks legitimate access) is a functionality bug, not a security vulnerability → **REJECT** with `rejection_reason: defensive_failure` and surface it under Recommended Actions. (One terminal outcome — do not also "cap at LOW"; that double-path made the rating non-reproducible.)
10. **Prerequisite chains affect severity.** Count the admin/config steps required *before* the weakness is reachable (privileged setup steps, not the steps of the person who triggers it), then downgrade: **2–3 prerequisites → −1 level, 4+ → −2 levels, floor at LOW.** CRITICAL is exempt from downgrade **because for RCE / data-loss impact dominates likelihood** — state this rationale so raters apply it consistently. Document the full prerequisite chain.
11. **No reassurance without evidence.** A non-issue cites the file:line of the control that makes the code safe. "No grep hits", a tool that did not run, or a pattern the scanner does not understand is a coverage gap: record it as `not_assessed` in the coverage ledger, never as a non-issue.
12. **Finding frontmatter is the single source of truth.** `remediation.json` is generated from it by `scripts/audit-state.mjs`, never written by hand. Run the script after every phase that writes findings; it must exit 0 before the report is assembled.

**Principles shared with all agents:**
- Never trust documentation or test names. Read source code and test bodies.
- If you cannot say who can do what they should not, it is a recommendation, not a finding.
- Separate agent verifies findings — detection ≠ verification.
- Verify reachability before analyzing impact. Cross-reference with the recon entry point table.

---

## Mode Selection

Choose mode based on the entry point count from the Phase 0 pre-pass (completed by recon); on an incremental run (`--since`), on the number of re-audit targets:

```
Entry points found in Phase 1?
  ├── < 20   → Standard Mode  (single agent, full workflow, no subagents)
  ├── 20-50  → Triage Mode    (single agent + prioritized order: HIGH→MED→LOW)
  └── > 50   → Parallel Mode  (multi-agent pipeline described below)
```

**Standard Mode:** One agent runs all 4 phases sequentially. Use the checklist in `references/audit-checklist.md`, the Deep Dive loop, and produce the report per `references/report-template.md`. No subagents needed. Record coverage in `.security-audit/coverage/coordinator.json` as you go (Triage and Quick-Run modes too).

**Triage Mode:** One agent, but after Recon, group endpoints by risk domain (HIGH: auth/payments/admin/upload, MEDIUM: CRUD/search, LOW: health/static). Audit HIGH domains first. If context runs low, report what you have and mark uncovered areas.

**Parallel Mode:** Full multi-agent pipeline. Continue reading.

---

## Shared Knowledge Directory

All agents read from and write to `.security-audit/` in the project root. This is the "shared brain" of the audit.

```
.security-audit/
├── prepass.md               # Phase 0 output: entry points, Drizzle scope scan, dependency advisories, secret scan
├── tools/                   # raw tool output (osv.json, gitleaks.json with values redacted, entry-points.json, scope-scan.json, incremental.json on --since)
├── recon.md                 # Phase 1 output: exposed surface map, authorization map, triage
├── findings/                # One file per finding (raw → verified/rejected; remediation state in its frontmatter)
│   ├── auth-001.md
│   └── ...
├── non-issues/              # Areas examined and found secure, each citing the control's file:line
├── not-assessed.md          # Coverage gaps: checks that could not be done, and why
├── coverage/                # Coverage ledger, one JSON file per writer: entry points and classes checked, not applicable, not assessed
├── coverage.json            # GENERATED: the merged ledger (scripts/coverage.mjs --write)
├── tests/                   # Phase 3 regression tests for HIGH/CRITICAL, in the project's own runner (never in the source tree)
├── briefs/                  # Phase 2 per-auditor briefs (scripts/briefs.mjs)
├── test-quality.md          # Phase 4 output
├── summary.md               # Phase 5: the coordinator's own text (summary, top risks, actions)
├── report.md                # Final report, assembled by scripts/report-md.mjs
├── report.html              # Visual report (scripts/report-html.mjs)
├── history/<date>/          # Previous runs, archived by prepass --new-run; agents never read it
└── remediation.json         # GENERATED from finding frontmatter by scripts/audit-state.mjs (never hand-edited)
```

File formats are defined in `references/finding-format.md`. All agents use the same format.

`$SKILL_DIR` below means this skill's base directory (shown when the skill loads). Pass the absolute path to every agent that runs a script.

---

## Phase 0: Setup and Deterministic Pre-pass (every mode, every run)

Run this yourself before dispatching anything. It takes seconds.

```bash
# Audit files name unfixed weaknesses: ignore the directory before anything is written into it.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git check-ignore -q .security-audit/report.md || {
    [ -s .gitignore ] && [ -n "$(tail -c1 .gitignore)" ] && echo >> .gitignore
    echo ".security-audit/" >> .gitignore
  }
  git ls-files --error-unmatch .security-audit >/dev/null 2>&1 && echo "WARNING: .security-audit is tracked in git"
fi
node "$SKILL_DIR/scripts/prepass.mjs" --new-run   # add: --scope <targets> for a partial audit; --since <commit|last> replaces --new-run
```

- **`--new-run`** moves a previous audit into `.security-audit/history/<date>/` (agents never read it, so the new run cannot anchor on old results), recreates `findings/`, `non-issues/`, `tests/`, and records the workspace state that `workspace-check.mjs` compares against at the end. Re-running prepass later in the same audit is done without `--new-run`.
- **Read the project's own agent rules** (`CLAUDE.md`, `AGENTS.md`, `docs/RISK.md` or similar) for anything that limits what may run: secrets files, runtime version, data directories, servers. Add them to the rules block below.

- **Live progress (optional):** if the directory `~/.claude/skills/audit-live` exists, tell the user once, right after the pre-pass: "Live progress: the Audit pane opens by itself in a wide terminal; in a narrow one type /audit-live." If it does not exist, say nothing about it.
- **Tracked warning:** tell the user that earlier audit files (naming unfixed weaknesses) are in git history and whether the remote is public. Offer `git rm -r --cached .security-audit` plus a commit. Do not run it without their consent.
- **Hotspots (start here):** `prepass.md` opens with the riskiest entry points and config files, ranked by signals (sensitive area such as auth/SSO/login, admin, payments, webhooks, files, AI; public-by-design kinds; no guard in the handler; unscoped queries; dangerous sinks; risky auth/CORS/env config). This is the work order for recon and every auditor: audit the hotspots in your domain first, then the rest. It is a ranking, not a verdict.
- **`prepass.md`** also holds: every entry point found by framework convention (Next.js route handlers, pages, `"use server"` actions, proxy/middleware matcher, tRPC procedures, Hono/Express routes, pg-boss/BullMQ/cron jobs, AI SDK/MCP tools, Drupal routes); the Drizzle scope scan (query sites on owner-scoped tables that never reference the owner column); dependency advisories from osv-scanner (prod vs dev-only); secrets from gitleaks across the whole git history, values redacted.
- **Tools:** native `osv-scanner` / `gitleaks` if installed, otherwise their official docker images (pulled on first use). Any `NOT RUN` or `FAILED` line goes into `not-assessed.md`, and you tell the user how to enable it. Never fill the gap from memory: CVE knowledge in a model is stale by construction.

---

## Rules Block for Every Agent

Paste this block, completed with the project's own rules from Phase 0, into every dispatch (recon, auditors, verifiers, test quality). It was written from real incidents: a stray file in the project root, a regenerated data directory, a near-read of `.env`.

```
Project root: <abs path>. Audit dir (write ONLY here): <abs path>/.security-audit. SKILL_DIR: <abs path>.
- Never read, print or edit secret files (.env and similar). Never write a key, token, code, phone number or a person's text into any file; use placeholders.
- Modify nothing outside .security-audit/: no source edits, no state-changing git, no writes to the project's database or data directories. Run helper scripts with explicit arguments and with cwd inside .security-audit/; never run a project script without arguments from the project root.
- Tests: <exact command with the right runtime>. The project's test suite may write generated files; workspace-check.mjs reports that at the end.
- Start no servers and make no network requests. The only code the audit runs is the project's own test runner, the regression tests under .security-audit/tests/ and the skill's scripts. Scratch files and databases go to .security-audit/tests/tmp.
- Do not read .security-audit/history/ or any earlier audit. Files with `carried_from:` in their frontmatter come from the previous audit (incremental run): never edit, overwrite or re-verify them; number new files after the highest number already used in your range.
- <project-specific rules>
- Reply compactly: counts, ids with one-line titles, and anything you could not do. Details belong in the files.
```

Pass **paths, not contents**: agents read `recon.md`, `prepass.md`, briefs and findings themselves. Pasting them into prompts multiplies the coordinator's context on big projects.

---

## Pipeline: Parallel Mode

You are the **coordinator**. You dispatch agents, pass context, collect results, and assemble the report. You do NOT audit code yourself (except in Standard/Triage modes).

### Phase 1: Recon (1 agent, Sonnet)

Dispatch a single agent with the prompt from `agents/recon-scanner.md`.

**Provide:**
- The project path, the path of `.security-audit/prepass.md`, and the rules block
- Instruction to write output to `.security-audit/recon.md`, including the Authorization Map

**Wait for completion.** Use recon's compact reply; open `.security-audit/recon.md` only for the sections you need.

From the recon output, extract:
- Entry point count (confirms Parallel Mode)
- Triage table (domains with risk levels)
- Stack info (determines which patterns from `references/stack-patterns.md` to pass)
- Security claims (become verification targets)
- Authorization Map, especially "proximity-only" entry points (only guarded by proxy/middleware, a layout or a page)

---

### Phase 2: Parallel Audit (3-5 agents, Sonnet)

Dispatch category auditors **in parallel**. Each agent uses the prompt from `agents/category-auditor.md`.

**How to split work:** Group by functional domain from the triage table. Typical split:

| Agent | Categories | Focus |
|-------|-----------|-------|
| Auth Auditor | 2.1, 2.3, 2.10, 2.11 | Auth, tenant scope, rate limiting, business logic, docs-vs-reality. Resolves every Data Scope Scan candidate |
| Injection Auditor | 2.2, 2.4 | Injection, data exposure |
| Infra Auditor | 2.5, 2.7, 2.8, 2.12 | Headers, dependencies, crypto, logging. Triages the pre-pass dependency and secret rows |
| Concurrency Auditor | 2.9 | Race conditions, TOCTOU, double-submit |
| Upload Auditor | 2.6 | File upload (skip if no uploads in recon) |

Write the briefs first (checklist sections per auditor plus stack patterns for the languages actually in the repo); add `--brief name=2.1,2.3` pairs for a custom split, e.g. two auth auditors on a big project:

```bash
node "$SKILL_DIR/scripts/briefs.mjs"
```

**Provide each agent with:**
1. The paths of `.security-audit/recon.md`, `.security-audit/prepass.md` and its brief `.security-audit/briefs/<name>.md`, plus the rules block
2. Its domain from the triage table, in a few lines
3. **Its number range**: auditor k writes every file it creates, findings and non-issues alike, with numbers k01–k99 (first auditor 101–199, second 201–299, …). Two auditors share categories on big projects, and equal numbers overwrite each other's files.
4. The pre-pass sections they own: Entry Points + Authorization Map + Data Scope Scan to the Auth Auditor; Dependency Advisories + Secret Scan to the Infra Auditor; Entry Points to everyone; and every auditor gets the Hotspots rows in its domain as its first targets (plus the in-scope target list on a `--scope` run)
5. Instruction to write findings to `.security-audit/findings/`, non-issues to `.security-audit/non-issues/`, and its coverage ledger to `.security-audit/coverage/auditor-<name>.json` (format: Coverage Ledger in `references/finding-format.md`): one row per entry point or project-wide check and class it owns, `checked` with evidence, `not_applicable` or `not_assessed` with a reason. Coverage gaps go there, not into `not-assessed.md`

**All agents run in parallel** — their number ranges keep their files apart.

**Wait for all to complete.** Then:
1. Run `node "$SKILL_DIR/scripts/audit-state.mjs" --summary` and have the owning auditor fix any format problem now, before verification. The summary replaces reading every file. Then `node "$SKILL_DIR/scripts/coverage.mjs" --summary`: it must exit 0, and the classes it lists as not recorded and the entry points without a row are "not looked at". Send the owning auditor back for those that should have been covered; the rest reach Not Assessed by themselves.
2. Check that every Data Scope Scan candidate ended as a finding or a non-issue; send the Auth Auditor back for any that did not
3. Report progress to user: "Phase 2 complete. N raw findings across M categories."

---

### Phase 3: Deep Dive Verification (sharded verifiers + one COMBINE pass, session model)

This is the most critical phase. Use the prompt from `agents/deep-dive-verifier.md`.

**Shards.** Up to about 25 findings: one verifier. More: split into shards of at most about 25 by category family so related findings stay together (e.g. auth + rate-limit + business-logic + docs-vs-reality / injection + exposure + config + crypto + logging / concurrency + upload) and run the shard verifiers in parallel. On a 160-entry-point project (50 findings) two shards finished in about 14 minutes each, where a single verifier had not finished one pass after 13.

**Provide each shard verifier:** the rules block; the paths of `recon.md`, `prepass.md` and its shard's finding files; the Shard mode section of the verifier prompt; likely overlaps you noticed (cross-shard ones go to COMBINE, not rejected inside a shard); the loop rules: max 3 iterations, stop on set-convergence, never exit with a finding still `raw`.

**Test method.** For HIGH/CRITICAL the verifier writes one regression test in the project's own runner under `.security-audit/tests/`, asserting the correct behaviour, and runs it once against a scratch database: a failing test confirms the finding (`proof: test`). No standalone scripts and no requests to any host. Where the runner cannot reach the code or real secrets would be needed, `proof: static` with one line why. The tests are the starting point of Phase 6.

**If a verifier stops before its shard is done** (its completion notification arrives with files still `raw`): make sure it has really ended, re-dispatch the remaining files in verify-only mode, and tell the user what happened.

**Before re-dispatching any work over the same files, confirm the earlier agent has ended.** A "stopped" verifier in a real run kept writing while its replacements ran.

**COMBINE pass (one agent, after all shards):** the COMBINE mode section of the verifier prompt. It reads every shard's `chain-notes-*.md`, decides cross-shard duplicates with rule 6d (a docs-vs-reality finding whose only remedy is its partner's code fix is a duplicate), verifies candidate chains against the code, writes `chain-9NN.md` findings, and runs `audit-state.mjs --final`. Start Phase 4 at the same time as COMBINE.

**Wait for completion.** Then:
1. Run `node "$SKILL_DIR/scripts/audit-state.mjs" --final --summary`. It fails on any finding still `raw`, on invalid categories/severities/rejection codes, on verified findings without file:line or an Impact section, and on HIGH/CRITICAL without a proof label. Raw findings → re-dispatch a verify-only pass; format problems → fix the files. Repeat until it exits 0.
2. Dedup rule (applied by shards and COMBINE), keyed on **(vulnerability class, sink file:line)**, not sink alone:
   - **Same class + same sink** → duplicate. Keep the most complete analysis as canonical, reject the rest with `rejection_reason: duplicate_of_{canonical_id}`.
   - **Same sink, DIFFERENT class** (e.g. a SQLi and a missing-authorization/BOLA defect on the same query line) → **distinct, keep both** (different fixes).
   - **Same class across MULTIPLE sinks tracing to one root cause** (e.g. one shared unsafe merge helper) → **merge into one class finding** (`systematic: N locations`), not N listings.
3. Report: "Phase 3 complete. N verified, M rejected (D duplicates), K new. Final score: X."

---

### Phase 4: Test Quality (1 agent, Sonnet, time-boxed)

Dispatch a single agent with the prompt from `agents/test-quality-auditor.md`, in parallel with COMBINE.

**Provide:** the rules block; the path of `recon.md` (Test Inventory section); the list of verified ids and titles from `audit-state.mjs --summary`; output path `.security-audit/test-quality.md`; the time box (about 20 minutes of work).

**Mutation testing is off by default.** In a real run it was the slowest phase of the whole audit (62 minutes) and wrote a stray file into the project root. Run it only when the user passes `--mutation` or asks, and then only on a copy of the repository outside the project directory.

**Wait for completion.** Use the agent's compact reply (verdict, coverage counts, top missing tests).

---

### Phase 5: Report Assembly (you, the coordinator)

You write only `.security-audit/summary.md`, following the top of `references/report-template.md`: the title, Project Summary (from recon's reply), Executive Summary (counts and score from `audit-state.mjs --summary`, the test-quality verdict, Top 3 risks each with its proof label `test` or `static`), and Recommended Actions (prioritized; include best-practice notes from rejected findings and the production checks from Not Assessed). Everything else is generated, so you never read every finding into your context:

```bash
node "$SKILL_DIR/scripts/audit-state.mjs" --final --write --source baseline-from-audit   # Phase 5.5, remediation.json
node "$SKILL_DIR/scripts/workspace-check.mjs"    # what changed outside the audit dir during the run
node "$SKILL_DIR/scripts/coverage.mjs" --write   # validates the coverage ledger, merges it into coverage.json; must exit 0
node "$SKILL_DIR/scripts/report-md.mjs"          # summary.md + findings + non-issues + gaps → report.md
node "$SKILL_DIR/scripts/report-html.mjs"        # → report.html
```

If `workspace-check` reports changes, tell the user which files changed, the likely cause (usually the project's own test run), and whether any tracked file changed.

`.security-audit/report.html` is one self-contained file: verdict bar, "To fix" (red, by severity, with proof labels and the fix first), "Verified safe" (green, each item with the control's file:line), "Not assessed" (grey), hotspots, dependencies, secrets, and what the verifier filtered out. It names unfixed weaknesses with file and line: it stays in the gitignored directory and is never published (a public page must redact unfixed findings, see `public_safe`).

**Present the Executive Summary to the user immediately**, with the absolute path to `report.html`. Offer to show full findings on request.

---

### Phase 5.5: Remediation baseline (default — always runs at audit end)

The first line of the Phase 5 script sequence **always** generates `.security-audit/remediation.json`, so downstream tooling (e.g. a public security page) has the after-state contract:

- On a fresh audit every verified finding has no `remediation:` block yet, so the script records it as `open` with `public_safe: false`.
- When re-running on code that changed since the findings were written, first add a `remediation:` block (`status: fixed`, `fix_evidence`) to each finding whose fix is now present, then run the script.
- **Read-only for source code.** The script only reads finding files and writes `remediation.json`.

This guarantees the after-state artifact always exists after any audit. `--verify-fixes` re-runs exactly this pass on demand; **Phase 6 (fix)** updates the same file as findings get resolved.

---

### Phase 6: Remediation (optional, on request)

Read `references/remediation.md`. The after-state **baseline** is already written by Phase 5.5; this phase goes further — actually **fixing** findings (only when the user asks), one at a time with verification, and updating the after-state (`remediation:` blocks + `remediation.json`) as each is resolved. `--verify-fixes` recomputes the state from current code without changing anything.

Fixes one finding at a time (highest severity first), TDD where practical (start from the regression test in `.security-audit/tests/` when the finding has `proof: test`), verifying each fix is live in the current code before marking it done. Records a **structured, machine-readable after-state**:
- a `remediation:` block on each finding file (`status: fixed|partial|open|wont_fix|cannot_verify`, `fix_evidence`, `regression_test`); top-level `status` stays `verified`;
- then `node "$SKILL_DIR/scripts/audit-state.mjs" --write --source fix-applied` regenerates `.security-audit/remediation.json`, the single artifact downstream tooling reads. `--verify-fixes` does the same with `--source verified-only`.

**`public_safe` is `true` ONLY when a finding is `fixed`.** Downstream public surfaces (e.g. a public security page) use it to decide whether a finding's details may be shown — never publish the details of an unfixed weakness. `fixed` requires evidence the fix is present in current code (cited `file:line`); "I changed something" is not "fixed".

---

## Scoring Metric

Used in Phase 3 to measure progress and determine when to stop iterating.

```
score = (CRITICAL × 4) + (HIGH × 3) + (MEDIUM × 2) + (LOW × 1)
```

Only count findings with `status: verified`. The score is a **reporting metric** — it is NOT the loop's stop signal.

**Stop signal (set-convergence, not score delta):** stop Deep Dive when an iteration produces **zero new findings, zero status changes (`raw`→`verified`/`rejected`), and zero new chains** vs the previous iteration — or at the max-3 cap. Score delta = 0 is *not* a valid stop: an iteration that rejects one HIGH (−3) and adds one HIGH via EXPAND (+3) nets delta 0 while the finding set changed materially, and pure-rejection rounds yield a *negative* delta that the "=0" rule never matches. Compare the **set** (verified IDs + severities + chains), not the scalar.

---

## Agent Model Selection

| Phase | Agent | Model | Why |
|-------|-------|-------|-----|
| 1 | Recon Scanner | sonnet | Mechanical: file reading, pattern matching — cost over quality |
| 2 | Category Auditors | sonnet | Pattern matching, checklist verification — cost over quality |
| 3 | Deep Dive Verifier | inherit (omit `model`) | Judgment: confirmation, chain detection, REJECT decisions — run on the strongest model in the session |
| 4 | Test Quality | sonnet | Structured analysis of test files |

Pin `model` only where cost matters more than quality. Phase 3 shards and COMBINE inherit the session model. If a verifier is stopped by a safety classifier, follow the Phase 3 rule: change the method, never the model.

---

## Cost on Big Projects

Measured on one production project (161 entry points, hand-rolled Node router, 50 raw findings): about 2 h 10 min wall clock and about 4.8M subagent tokens. Recon took 0.4M, six auditors 2.8M, verification 0.8M (including a stopped first attempt), COMBINE 0.2M, test quality with mutation testing 0.5M. To spend less:
- start with `--scope top20` or one domain (`--scope auth`) and widen only where it finds something;
- merge small auditor domains (concurrency + upload) instead of one agent each;
- keep mutation testing off;
- pass paths, not contents, and use `audit-state.mjs --summary` instead of reading findings.

---

## Quick-Run Mode

For fast single-pass audit without subagents (any project size):
- Still run Phase 0 (gitignore + pre-pass); it costs seconds and is the only CVE and secret-history source
- Single agent runs all phases sequentially
- Apply EXPAND/TRACE/VERIFY/REJECT inline during Phase 2
- Skip Phase 3 Deep Dive loop
- Still write to `.security-audit/` for persistence
- Still run the Phase 5 script sequence at the end (`audit-state.mjs --final --write`, `workspace-check.mjs`, `coverage.mjs --write`, `report-md.mjs`, `report-html.mjs`)
- Work through the pre-pass Hotspots first; for an even faster pass combine with `--scope top20`
- Still produce full report with Non-Issues

Trades depth for speed. Use for initial assessments or time-constrained reviews.

---

## Stack Adaptation

This methodology is stack-agnostic. Phase 1 discovers the stack; Phase 2 adapts.

- Pass relevant patterns from `references/stack-patterns.md` to auditor agents
- Skip inapplicable categories (no uploads → skip 2.6, no crypto → skip 2.8)
- For frameworks with built-in protections (Django CSRF, Rails strong params), verify enabled and not bypassed

---

## Reference Files

| File | When to read | Contents |
|------|-------------|----------|
| `references/audit-checklist.md` | Phase 2 dispatch | Full 12-category checklist with all check items |
| `references/report-template.md` | Phase 5 report assembly | Markdown report template |
| `references/stack-patterns.md` | Phase 2 dispatch | Language/framework-specific grep patterns |
| `references/finding-format.md` | All phases | File formats for findings, non-issues, recon output |
| `references/remediation.md` | Phase 6 | Remediation workflow + `remediation.json` contract + `public_safe` redaction flag |
| `scripts/prepass.mjs` | Phase 0 | Entry points, Drizzle scope scan, osv-scanner, gitleaks → `prepass.md` |
| `scripts/audit-state.mjs` | After Phases 2, 3, 6 and 5.5 | Validates finding frontmatter; `--write` generates `remediation.json` |
| `scripts/report-html.mjs` | End of Phase 5 / after Phase 6 | Renders `report.html` (to fix / verified safe / not assessed) from the finding files |
| `scripts/briefs.mjs` | Phase 2 dispatch | One brief per auditor: its checklist sections + stack patterns for the repo's languages |
| `scripts/report-md.mjs` | Phase 5 | Assembles `report.md` from the coordinator's `summary.md` and the audit files |
| `scripts/workspace-check.mjs` | Phase 5 | Lists files changed outside `.security-audit/` since prepass `--new-run` |
| `scripts/coverage.mjs` | After Phase 2, Phase 5 | Validates the coverage ledger (`references/coverage-ledger.schema.json`); report-md and report-html derive Coverage and Not Assessed from it |
| `agents/recon-scanner.md` | Phase 1 dispatch | Recon agent prompt |
| `agents/category-auditor.md` | Phase 2 dispatch | Category auditor agent prompt |
| `agents/deep-dive-verifier.md` | Phase 3 dispatch | Deep Dive verifier agent prompt |
| `agents/test-quality-auditor.md` | Phase 4 dispatch | Test quality agent prompt |

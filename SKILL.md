---
name: security-audit
description: >-
  Use when asked to audit, pentest, or review the security of a codebase
  or application. Triggers on security audit, vulnerability assessment,
  find vulnerabilities, pentest this, check for security issues, review
  auth implementation, or assess test quality from a security perspective.
---

# Security Audit

Evidence-based, measurement-driven, stack-agnostic security audit.
Uses a multi-agent pipeline: Recon → Parallel Audit → Verification → Test Quality → Report.

## Hard Rules

These gates apply to ALL agents in the pipeline. Violating them invalidates the audit.

1. **No assumed vulnerabilities.** Cannot point to file:line → not a finding.
2. **No severity inflation.** No concrete exploit path → LOW at best.
3. **Every finding requires ALL of:** file path, line number, code snippet, numbered exploit steps.
4. **REJECT gate is mandatory.** 5-part checklist before recording any finding.
5. **If documentation is absent**, do not penalize — audit the code as-is.
6. **Run the tests.** Report results honestly.
7. **Record Non-Issues.** Areas examined and found secure must be documented.

**Principles shared with all agents:**
- Never trust documentation or test names. Read source code and test bodies.
- If you cannot write concrete exploit steps, it is a recommendation, not a finding.
- Separate agent verifies findings — detection ≠ verification.

---

## Mode Selection

Choose mode based on entry point count from Phase 1 recon:

```
Entry points found in Phase 1?
  ├── < 20   → Standard Mode  (single agent, full workflow, no subagents)
  ├── 20-50  → Triage Mode    (single agent + prioritized order: HIGH→MED→LOW)
  └── > 50   → Parallel Mode  (multi-agent pipeline described below)
```

**Standard Mode:** One agent runs all 4 phases sequentially. Use the checklist in `references/audit-checklist.md`, the Deep Dive loop, and produce the report per `references/report-template.md`. No subagents needed.

**Triage Mode:** One agent, but after Recon, group endpoints by risk domain (HIGH: auth/payments/admin/upload, MEDIUM: CRUD/search, LOW: health/static). Audit HIGH domains first. If context runs low, report what you have and mark uncovered areas.

**Parallel Mode:** Full multi-agent pipeline. Continue reading.

---

## Shared Knowledge Directory

All agents read from and write to `.security-audit/` in the project root. This is the "shared brain" of the audit.

```
.security-audit/
├── recon.md                 # Phase 1 output: attack surface map + triage
├── findings/                # One file per finding (raw → verified/rejected)
│   ├── auth-001.md
│   ├── injection-001.md
│   └── ...
├── non-issues/              # Areas examined and found secure
│   ├── non-auth-001.md
│   └── ...
├── test-quality.md          # Phase 4 output
└── report.md                # Final assembled report
```

**Create this directory at the start of the audit:**
```bash
mkdir -p .security-audit/findings .security-audit/non-issues
```

File formats are defined in `references/finding-format.md`. All agents use the same format.

---

## Pipeline: Parallel Mode

You are the **coordinator**. You dispatch agents, pass context, collect results, and assemble the report. You do NOT audit code yourself (except in Standard/Triage modes).

### Phase 1: Recon (1 agent, Sonnet)

Dispatch a single agent with the prompt from `agents/recon-scanner.md`.

**Provide:**
- The project path
- Instruction to write output to `.security-audit/recon.md`

**Wait for completion, then read `.security-audit/recon.md`.**

From the recon output, extract:
- Entry point count (confirms Parallel Mode)
- Triage table (domains with risk levels)
- Stack info (determines which patterns from `references/stack-patterns.md` to pass)
- Security claims (become verification targets)

---

### Phase 2: Parallel Audit (3-5 agents, Sonnet)

Dispatch category auditors **in parallel**. Each agent uses the prompt from `agents/category-auditor.md`.

**How to split work:** Group by functional domain from the triage table. Typical split:

| Agent | Categories | Focus |
|-------|-----------|-------|
| Auth Auditor | 2.1, 2.3, 2.10, 2.11 | Auth, rate limiting, business logic, docs-vs-reality |
| Injection Auditor | 2.2, 2.4 | Injection, data exposure |
| Infra Auditor | 2.5, 2.7, 2.8, 2.12 | Headers, dependencies, crypto, logging |
| Concurrency Auditor | 2.9 | Race conditions, TOCTOU, double-submit |
| Upload Auditor | 2.6 | File upload (skip if no uploads in recon) |

**Provide each agent with:**
1. Full content of `.security-audit/recon.md`
2. Their assigned categories from `references/audit-checklist.md` (paste the relevant sections — do NOT tell them to read the file)
3. Relevant stack patterns from `references/stack-patterns.md` (paste only patterns for detected language)
4. Instruction to write findings to `.security-audit/findings/` and non-issues to `.security-audit/non-issues/`

**All agents run in parallel** — they write to different files so no conflicts.

**Wait for all to complete.** Then:
1. Read all files in `.security-audit/findings/`
2. Read all files in `.security-audit/non-issues/`
3. Count findings by category, compute preliminary score
4. Report progress to user: "Phase 2 complete. N raw findings across M categories."

---

### Phase 3: Deep Dive Verification (1 agent, Opus)

This is the most critical phase. Dispatch a single agent with the prompt from `agents/deep-dive-verifier.md`.

**Provide:**
1. Full content of `.security-audit/recon.md`
2. Full content of ALL finding files from `.security-audit/findings/`
3. Instruction: max 3 iterations, stop if score delta = 0
4. Current score from your preliminary count

**This agent:**
- Reads code independently (does NOT trust auditor reports)
- Runs EXPAND → TRACE → COMBINE → VERIFY → RATE → REJECT on each finding
- Cross-references findings from DIFFERENT auditors (auth bypass + injection = chain)
- Updates finding files: `status: verified` or `status: rejected`
- Writes new findings discovered during EXPAND

**Wait for completion.** Then:
1. Re-read all finding files
2. Count verified vs rejected
3. Compute final score
4. Report: "Phase 3 complete. N verified, M rejected, K new. Final score: X."

---

### Phase 4: Test Quality (1 agent, Sonnet)

Dispatch a single agent with the prompt from `agents/test-quality-auditor.md`.

**Provide:**
1. Content of `.security-audit/recon.md` (test inventory section)
2. List of verified finding IDs and titles
3. Instruction to write output to `.security-audit/test-quality.md`

**Wait for completion.** Read `.security-audit/test-quality.md`.

---

### Phase 5: Report Assembly (you, the coordinator)

Read `references/report-template.md` and assemble the final report from:

- `.security-audit/recon.md` → Project Summary
- `.security-audit/findings/` (status: verified) → Findings section, ordered by severity
- `.security-audit/findings/` (status: rejected, with best-practice notes) → Recommended Actions
- `.security-audit/non-issues/` → Non-Issues table
- `.security-audit/test-quality.md` → Test Quality Details
- Recon security claims + finding statuses → Documentation vs Reality table
- Score computation → Executive Summary

Write the final report to `.security-audit/report.md`.

**Present the Executive Summary to the user immediately.** Offer to show full findings on request.

---

## Scoring Metric

Used in Phase 3 to measure progress and determine when to stop iterating.

```
score = (CRITICAL × 4) + (HIGH × 3) + (MEDIUM × 2) + (LOW × 1)
```

Only count findings with `status: verified`. Track score after each Deep Dive iteration. Delta = 0 → stop.

---

## Agent Model Selection

| Phase | Agent | Recommended Model | Why |
|-------|-------|-------------------|-----|
| 1 | Recon Scanner | sonnet | Mechanical: file reading, pattern matching |
| 2 | Category Auditors | sonnet | Pattern matching, checklist verification |
| 3 | Deep Dive Verifier | opus | Judgment: exploit verification, chain detection, REJECT decisions |
| 4 | Test Quality | sonnet | Structured analysis of test files |

Override with `model` parameter when dispatching agents. Use opus for Phase 3 — this is where false positive rejection and cross-domain chain detection happen.

---

## Quick-Run Mode

For fast single-pass audit without subagents (any project size):
- Single agent runs all phases sequentially
- Apply EXPAND/TRACE/VERIFY/REJECT inline during Phase 2
- Skip Phase 3 Deep Dive loop
- Still write to `.security-audit/` for persistence
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
| `references/audit-checklist.md` | Phase 2 dispatch | Full 10-category checklist with all check items |
| `references/report-template.md` | Phase 5 report assembly | Markdown report template |
| `references/stack-patterns.md` | Phase 2 dispatch | Language/framework-specific grep patterns |
| `references/finding-format.md` | All phases | File formats for findings, non-issues, recon output |
| `agents/recon-scanner.md` | Phase 1 dispatch | Recon agent prompt |
| `agents/category-auditor.md` | Phase 2 dispatch | Category auditor agent prompt |
| `agents/deep-dive-verifier.md` | Phase 3 dispatch | Deep Dive verifier agent prompt |
| `agents/test-quality-auditor.md` | Phase 4 dispatch | Test quality agent prompt |

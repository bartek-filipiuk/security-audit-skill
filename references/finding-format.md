# Finding & Non-Issue File Formats

All agents write to `.security-audit/` using these formats.
One file per finding/non-issue. Filename: `{category}-{NNN}.md` (e.g., `injection-101.md`). NNN comes from the writer's number range so parallel agents never overwrite each other: Phase 2 auditor k uses k01–k99 for findings and non-issues alike, verifier EXPAND uses 8NN, COMBINE chains use 9NN.
`node $SKILL_DIR/scripts/audit-state.mjs` validates these files (enums, required sections, proof labels, remediation consistency). Frontmatter supports `key: value`, one nested block (`remediation:`), `- item` lists and `["a", "b"]` arrays; no multi-line `|` / `>` values.

**Canonical category set** (single source of truth — keep `report-template.md` and the agent prompts in sync with this): the 12 audit categories `auth, injection, rate-limit, exposure, config, upload, dependency, crypto, concurrency, docs-vs-reality, business-logic, logging` (mapping to checklist §2.1–§2.12), plus `test-gap` (Phase 4 test-quality findings) and `chain` (cross-domain chains discovered in COMBINE). Note `docs-vs-reality` (§2.10) is a valid finding category — it was previously missing from the enum. Classes without their own category go where the fix lives: SSRF → `injection`, CSRF and tenant-scope bugs → `auth`, secrets in git history → `exposure`.

## Finding Format

```markdown
---
id: {category}-{NNN}
category: auth | injection | rate-limit | exposure | config | upload | dependency | crypto | concurrency | docs-vs-reality | business-logic | logging | test-gap | chain
severity: CRITICAL | HIGH | MEDIUM | LOW
status: raw | verified | rejected   # the audit verdict only; never `fixed` (remediation state lives below)
source_agent: recon | auditor-{name} | verifier
proof: test | static  # REQUIRED for verified HIGH/CRITICAL: test = a regression test fails today (see ## Regression Test), static = code reading only
rejection_reason: ""  # When status=rejected. Starts with a code: dead_code | unreachable | defensive_failure | best_practice | duplicate_of_{id} | no_evidence; optional " — short reason" after it
prerequisite_count: 0  # Number of admin/config steps required before the weakness is reachable
remediation:           # OPTIONAL — added by Phase 6 (fix or --verify-fixes), only on verified findings
  status: open         # fixed | partial | open | wont_fix | cannot_verify
  fixed_at: ""         # YYYY-MM-DD when fixed
  fix_commit: ""       # optional
  fix_evidence: []     # ["path:line"] proof the fix is live in current code (REQUIRED for `fixed`)
  regression_test: ""  # "path:line" or empty
  verification: ""     # one line: what now prevents the behaviour (REQUIRED rationale for `wont_fix`)
  public_safe: false   # true ONLY when status: fixed; audit-state.mjs recomputes it for remediation.json
---

## Title
[Short descriptive title]

## Evidence
- **File**: `path/to/file.py:42`
- **Code**:
```
[relevant code snippet, 5-15 lines]
```

## TRACE
- **Source**: [where user input enters] (`file:line`)
- **Transformations**: [each function/middleware that modifies it]
- **Sink**: [where consumed: DB, response, file, exec, log] (`file:line`)
- **Sanitization**: [what exists between source and sink]
- **Verdict**: SAFE | VULNERABLE | PARTIAL

## Impact
[One to three sentences: who can do what they should not, through which entry point, and what data or action is affected. Name the actor by role ("anyone", "a signed-in user", "a member of another organization") and describe the effect, not a procedure.]

## Regression Test
[HIGH/CRITICAL. proof: test → the test's path under `.security-audit/tests/`, what it asserts, and the relevant output of the failing run. proof: static → one line on why no test was written.]

## Chained With
- [other finding IDs, if applicable, or "none"]

## Recommendation
[specific fix]

## Test Coverage
tested | untested | test exists but insufficient

## Rejection Note
[When status=rejected: explain why. Reference the specific REJECT gate check that failed (6a/6b/6c/6d). If duplicate, reference the canonical finding ID.]

## Remediation
[Added by Phase 6 when fixed: what changed + why, mirroring the `remediation:` frontmatter block. The Evidence and Impact above are treated as sensitive — downstream public surfaces (e.g. a public security page) redact them unless `remediation.public_safe: true`.]
```

## Non-Issue Format

```markdown
---
id: non-{category}-{NNN}
category: auth | injection | rate-limit | exposure | config | upload | dependency | crypto | concurrency | docs-vs-reality | business-logic | logging | test-gap | chain
source_agent: auditor-{name}
---

## Area Examined
[what was checked]

## Why Not Vulnerable
[specific reason with evidence]

## Evidence
- **File**: `path/to/file.py:42`
- **Code or config**: [relevant snippet showing the protection is in place]
```

A non-issue without the control's file:line is not allowed. When something could not be checked, add a row to `.security-audit/not-assessed.md` instead:

```markdown
| Category | Check | Why not assessed |
|---|---|---|
| dependency | CVE scan | osv-scanner and docker unavailable (prepass: NOT RUN) |
```

## Recon Output Format (.security-audit/recon.md)

```markdown
# Recon Summary

## Stack
- Languages: [list]
- Frameworks: [list]
- Databases: [list]
- External services: [list]
- Deployment: [method]

## Entry Points
| # | Kind | Route/Handler | File:line | Method |
|---|------|--------------|-----------|--------|
(start from prepass.md; add what it cannot see)

## Authorization Map (claims to verify)
| # | Entry point | Authn at | Authz at | Scope at (id from session or request?) |
|---|-------------|----------|----------|-----------------------------------------|
Levels: proxy | layout | page | handler | action | procedure | DAL | query | none-found, each with file:line.

### Proximity-only entry points
[entry points whose only control is in proxy/middleware, a layout or a page]

## Auth System
[description: JWT/sessions/OAuth/API keys, where validated, middleware chain]

## Dependencies
- Total: [N]
- Pinned: [N/N] ([%])
- Lockfile: [yes/no]
- Advisory mechanism: [Dependabot/Renovate/none]
- Pre-pass advisories: [N vulnerable packages, highest CVSS, prod vs dev-only] (from prepass.md, never from memory)

## Not assessed
[pre-pass tools that were NOT RUN or FAILED, and anything else recon could not map]

## Security Claims
| # | Source | Claim | To Verify In |
|---|--------|-------|-------------|

## Test Inventory
- Runner: [jest/pytest/go test/etc.]
- Total tests: [N]
- Pass: [N] | Fail: [N] | Skip: [N]
- Runtime: [Xs]
- Security tests: [list files]
- Pre-existing failures: [list or "none"]

## Triage (for parallel mode)
| Domain | Risk | Entry Points | Categories to Audit |
|--------|------|-------------|-------------------|
| auth   | HIGH | [list]      | 2.1, 2.3          |
| api    | HIGH | [list]      | 2.2, 2.4, 2.9     |
| infra  | MED  | [list]      | 2.5, 2.7, 2.8     |
| upload | MED  | [list]      | 2.6                |
```

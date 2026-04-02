# Finding & Non-Issue File Formats

All agents write to `.security-audit/` using these formats.
One file per finding/non-issue. Filename: `{category}-{NNN}.md` (e.g., `injection-001.md`).

## Finding Format

```markdown
---
id: {category}-{NNN}
category: auth | injection | exposure | config | upload | rate-limit | dependency | crypto | concurrency | business-logic | logging
severity: CRITICAL | HIGH | MEDIUM | LOW
status: raw | verified | rejected
source_agent: recon | auditor-{name} | verifier
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

## Exploit Steps
1. [concrete step]
2. [concrete step]
3. [expected result]

## Chained With
- [other finding IDs, if applicable, or "none"]

## Recommendation
[specific fix]

## Test Coverage
tested | untested | test exists but insufficient
```

## Non-Issue Format

```markdown
---
id: non-{category}-{NNN}
category: auth | injection | exposure | config | upload | rate-limit | dependency | crypto | concurrency | business-logic | logging
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
| # | Route/Handler | File | Auth Required | Method |
|---|--------------|------|---------------|--------|

## Auth System
[description: JWT/sessions/OAuth/API keys, where validated, middleware chain]

## Dependencies
- Total: [N]
- Pinned: [N/N] ([%])
- Lockfile: [yes/no]
- Advisory mechanism: [Dependabot/npm audit/none]
- Notable: [any concerning deps]

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

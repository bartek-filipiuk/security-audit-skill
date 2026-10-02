# Security Audit Report Template

The coordinator writes only the top of this template to `.security-audit/summary.md`: the title, Project Summary, Executive Summary and Recommended Actions. `scripts/report-md.mjs` appends everything from "## Findings" down (findings, non-issues, not assessed, documentation vs reality, test quality, side effects, filtered out) from the audit files, so the report always matches them.

```markdown
# Security Audit Report

## Project Summary
- Stack: [auto-detected from Phase 1]
- Attack surface: [entry points count, auth method, file handling, external services]
- Dependencies: [total count, pinned %, advisory mechanism]
- Lines of code audited: [estimate]
- Test suite: [X tests, pass/fail/skip counts, runner, config notes]
- Pre-pass: [N entry points · N scope candidates · dependency scan status · secret scan status]

## Executive Summary
- Critical findings: [count]
- High: [count] | Medium: [count] | Low: [count]
- Deep Dive score: [final metric value] (after [N] iterations)
- Test quality: [STRONG / ADEQUATE / WEAK / UNRELIABLE]
- Top 3 risks: [one-line each, with its proof label: dynamic (demonstrated) or static (code reading only)]
- Not assessed: [count, or "none"]

## Findings

### [F1] Title
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Category**: canonical set from `finding-format.md` — `auth | injection | rate-limit | exposure | config | upload | dependency | crypto | concurrency | docs-vs-reality | business-logic | logging | test-gap | chain`
- **Evidence**: `file:line` — what the code does
- **TRACE**:
  - Source: [where user input enters] (file:line)
  - Transformations: [each function/middleware that modifies it, in order]
  - Sink: [where consumed: DB, response, file, exec, log] (file:line)
  - Sanitization: [what exists between source and sink]
  - Verdict: SAFE / VULNERABLE / PARTIAL
- **Exploit scenario**: concrete numbered attack steps
- **Proof** (HIGH/CRITICAL): dynamic — [command + observed result] | static — [why it was not run]
- **Chained with**: [other finding IDs, if applicable]
- **Recommendation**: specific fix
- **Test coverage**: tested / untested / test exists but insufficient

[repeat for each finding, ordered by severity]

## Non-Issues (examined but not vulnerable)
| # | Area Examined | Why Not Vulnerable | Evidence |
|---|--------------|-------------------|----------|

[Document areas you investigated that turned out to be secure.
This prevents re-investigation and demonstrates audit thoroughness.]

## Not Assessed (coverage gaps)
| Category | Check | Why not assessed | How to enable |
|----------|-------|------------------|---------------|

[From `not-assessed.md` and pre-pass NOT RUN/FAILED lines. An empty table must be earned: each row here is something nobody checked, not something that is safe.]

## Documentation vs Reality
| # | Claimed | Status | Evidence |
|---|---------|--------|----------|

## Test Quality Details
| Test file | Verdict | Issues |
|-----------|---------|--------|

## Recommended Actions (prioritized)
1. [CRITICAL fixes]
2. [HIGH fixes]
3. [Missing tests to add]
4. [Documentation corrections]
5. [Best-practice recommendations — items that failed REJECT as findings but are still worth improving]
```

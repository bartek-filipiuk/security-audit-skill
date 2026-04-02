# Security Audit Report Template

Use this template to produce the final report after completing all 4 phases.

```markdown
# Security Audit Report

## Project Summary
- Stack: [auto-detected from Phase 1]
- Attack surface: [entry points count, auth method, file handling, external services]
- Dependencies: [total count, pinned %, advisory mechanism]
- Lines of code audited: [estimate]
- Test suite: [X tests, pass/fail/skip counts, runner, config notes]

## Executive Summary
- Critical findings: [count]
- High: [count] | Medium: [count] | Low: [count]
- Deep Dive score: [final metric value] (after [N] iterations)
- Test quality: [STRONG / ADEQUATE / WEAK / UNRELIABLE]
- Top 3 risks: [one-line each]

## Findings

### [F1] Title
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Category**: auth | injection | exposure | config | upload | rate-limit | dependency | crypto | concurrency | test-gap
- **Evidence**: `file:line` — what the code does
- **TRACE**:
  - Source: [where user input enters] (file:line)
  - Transformations: [each function/middleware that modifies it, in order]
  - Sink: [where consumed: DB, response, file, exec, log] (file:line)
  - Sanitization: [what exists between source and sink]
  - Verdict: SAFE / VULNERABLE / PARTIAL
- **Exploit scenario**: concrete numbered attack steps
- **Chained with**: [other finding IDs, if applicable]
- **Recommendation**: specific fix
- **Test coverage**: tested / untested / test exists but insufficient

[repeat for each finding, ordered by severity]

## Non-Issues (examined but not vulnerable)
| # | Area Examined | Why Not Vulnerable | Evidence |
|---|--------------|-------------------|----------|

[Document areas you investigated that turned out to be secure.
This prevents re-investigation and demonstrates audit thoroughness.]

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

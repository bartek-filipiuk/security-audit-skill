# Remediation Phase

Fix findings safely, one at a time, with verification — **and record a structured, machine-readable "after" state** so downstream tooling (e.g. a public security page) can show a truthful before→after. ONLY the *fixing* runs when the user explicitly requests fixes; the *verification-only* mode (below) may run on request to (re)compute remediation state without changing code.

## Why structured remediation state

The audit (`findings/`, `report.md`) is a **point-in-time snapshot**: what was found + the recommended fix. It does NOT, by itself, record whether a finding was later fixed. Without that, nobody downstream can honestly say "this was fixed." This phase closes that gap by writing two things on every fix:

1. A **`remediation:` frontmatter block** on the finding file (per-finding truth).
2. A consolidated **`.security-audit/remediation.json`** (the single artifact downstream tools read).

**Hard rule — evidence-gated, never optimistic.** A finding is only `fixed` if you verified the fix in the *current* code (cited `file:line`) AND the exploit path is now blocked. No evidence → not `fixed`. "I changed something" is not "fixed."

**Single source of truth.** You edit only the finding's `remediation:` block. `remediation.json` is generated from the findings by `node $SKILL_DIR/scripts/audit-state.mjs --write --source <fix-applied|verified-only>`, which also refuses inconsistent state (`fixed` without `fix_evidence`, `public_safe: true` on an open finding, a remediation block on a rejected finding). Never hand-edit `remediation.json`.

## Preconditions

- Audit complete, findings in `.security-audit/findings/`
- For fixing: user explicitly requested remediation; clean git state (or user accepts uncommitted changes)
- For verification-only: just a completed audit (code present to re-check against)

## Two modes

| Mode | Trigger | Touches code? | Writes |
|---|---|---|---|
| **Fix** | "fix the findings" / Phase 6 on request | yes (one finding at a time, TDD) | finding `remediation:` block, then `audit-state.mjs --write --source fix-applied` |
| **Verify-only** | **default last step of every audit (Phase 5.5 baseline)**, `--verify-fixes`, or "recheck what's fixed" | no | finding `remediation:` block, then `audit-state.mjs --write --source verified-only` |

Verify-only exists because fixes are sometimes applied outside this skill (manual PRs, another session). It re-reads each finding's cited evidence in current code and classifies status from reality — the same classification the Fix mode records after patching.

## Workflow Per Finding (Fix mode)

Fix highest-severity first. For each finding:

### 1. Re-read the finding
Load the finding file. Confirm the vulnerability still exists (code may have changed — if it's already gone, jump to step 6 and record `fixed` with current evidence).

### 2. Understand the fix
See the severity Hard Rules in `SKILL.md` if severity is unclear. Plan the minimal fix that:
- Addresses root cause, not symptoms
- Doesn't break existing functionality
- Follows the codebase's existing patterns

### 3. Write a failing test first (TDD)
When practical, write a test that reproduces the vulnerability (it should fail), then fix. If the finding has `proof: dynamic`, start from its PoC in `.security-audit/poc/` and move it into the project's test suite. The test path goes into `regression_test`.

### 4. Apply the fix
Make the minimal change. Don't refactor unrelated code.

### 5. Verify
- Run the new test (should pass)
- Run the existing test suite (should not regress)
- Re-read the finding's exploit scenario — confirm it's now blocked **in the current code**, and note the exact `file:line` proving it

### 6. Record structured remediation state (REQUIRED)
Do BOTH:

**(a)** Add/update the `remediation:` frontmatter block on the finding file. Top-level `status` stays `verified`: it is the audit verdict, not the fix state. Also append a human `## Remediation` section (what changed + why).

**(b)** Regenerate `.security-audit/remediation.json`: `node $SKILL_DIR/scripts/audit-state.mjs --write --source fix-applied`. It must exit 0.

## Classification (both modes)

For each verified finding, classify `remediation_status`:

| Status | Meaning | `public_safe` |
|---|---|---|
| `fixed` | Fix present in current code (cited `file:line`) AND exploit path blocked AND (ideally) a regression test | `true` |
| `partial` | Mitigated but not fully closed, or fix present without a regression test pinning it | `false` |
| `open` | Not fixed yet | `false` |
| `wont_fix` | Accepted risk / by design — must include a one-line rationale | `false` |
| `cannot_verify` | Cited code not found / unreadable / ambiguous — state why | `false` |

**`public_safe` rule (do not deviate):** ONLY `fixed` is `public_safe: true`. Everything else is `false`. Downstream public surfaces (e.g. a public security page) use this flag to decide whether the exploit detail may be shown — a working exploit for an unfixed bug must never be published. `rejected` findings and `non-issues/` are not remediation items; they belong to the "cleared" audit trail, not this list.

## remediation.json schema (the contract)

Single file at `.security-audit/remediation.json`, generated by `scripts/audit-state.mjs`. Downstream tooling reads ONLY this file.

```jsonc
{
  "schema_version": "1.0",
  "project": "<basename>",
  "audited_commit": "<commit from report.md, if known>",
  "audit_date": "<YYYY-MM-DD from report.md>",
  "generated_at": "<YYYY-MM-DD or ISO — when this state was last written>",
  "source": "baseline-from-audit" | "verified-only" | "fix-applied",
  "summary": {
    "verified_total": <int>,
    "fixed": <int>, "partial": <int>, "open": <int>,
    "wont_fix": <int>, "cannot_verify": <int>,
    "cleared": { "rejected": <int>, "non_issues": <int> }   // from report.md, for the trust signal
  },
  "findings": [
    {
      "id": "auth-003",
      "category": "auth",
      "severity": "MEDIUM",                 // CRITICAL|HIGH|MEDIUM|LOW
      "title": "<one line>",
      "proof": "dynamic",                   // dynamic|static, copied from the finding
      "remediation_status": "fixed",        // fixed|partial|open|wont_fix|cannot_verify
      "fixed_at": "2026-05-30",             // omit if not fixed
      "fix_commit": "abc1234",              // optional
      "fix_evidence": ["apps/web/src/lib/server/auth.ts:26-29"],
      "verification": "rateLimit:{enabled:true,window:60,max:5} now present; auth.test.ts:42 asserts 6th req → 429",
      "regression_test": "apps/web/src/lib/server/auth.test.ts:42",  // omit if none
      "public_safe": true
    }
    // ... one entry per VERIFIED finding. Rejected findings excluded.
  ]
}
```

Notes:
- One entry per **verified** finding (the things that were real). Rejected findings stay out (counted in `summary.cleared.rejected`).
- Keep `findings[].title` short and non-sensitive — it appears on a potentially public page even when the finding is still `open` (the title alone must not be a how-to).
- `fix_evidence` is the proof the fix is live in current code — required for `fixed`, helpful for `partial`.

## Frontmatter `remediation:` block (per finding)

Mirror the json entry on the finding file (source of truth per finding):

```yaml
---
id: auth-003
severity: MEDIUM
status: verified         # the audit verdict; never "fixed"
category: auth
remediation:
  status: fixed          # fixed|partial|open|wont_fix|cannot_verify
  fixed_at: 2026-05-30
  fix_commit: abc1234
  fix_evidence: ["apps/web/src/lib/server/auth.ts:26-29"]
  regression_test: "apps/web/src/lib/server/auth.test.ts:42"
  verification: "rateLimit enabled; 6th anon sign-in → 429 (test asserts)"
  public_safe: true
---
```

## After All Fixes

- Re-run the relevant category audits to confirm fixes
- Run `audit-state.mjs --write`: the counts in `remediation.json` are derived from the findings, so they always match
- Run `report-html.mjs` again: fixed findings move from "To fix" to "Fixed" in `report.html`
- Update `report.md` with a "Remediation status" line per finding
- Summarize what was fixed, what remains, and any new risks introduced

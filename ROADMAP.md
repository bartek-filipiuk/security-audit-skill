# Roadmap

No dates. Four lanes, read left to right: Now, Next, Later, Ideas. Each item has a stable id
(R01…), one line on the value for the user and one line on the done criterion. The public copy is
https://security-audit.dev/roadmap (`src/roadmap.ts` in the landing repo); keep the two in sync.
Tasks live in devince-crm under the same ids.

Rules that apply to every item:
- A stack profile ships only with its own benchmark app (seeded bugs and decoys), scored the same way as Ledgerly.
- Deterministic tool output is a candidate for the auditors, never a finding without verification in the code.
- Nothing in the skill describes or performs attacks: findings state the impact and carry a regression test.

## Now

- **R01 Incremental audit, `--since <commit>`.** Audit only the entry points whose code changed since the
  last audit or a given commit; carry the rest of the report over from the previous run.
  Done when: re-auditing a small change on Ledgerly costs a fraction of a full run, measured in tokens and minutes.
- **R02 Supabase and Firebase profile.** RLS policies, storage policies, service-role keys in the client,
  Firestore rules. Done when: a benchmark app for this stack exists and the profile scores on it.
- **R03 Exact benchmark scoring.** Match findings to the answer key by file and line, not keywords.
  Done when: every Ledgerly match is exact and the scorer reports no loose matches.

- **R19 One-command install.** `npx @devince/apps install <link from the e-mail>` downloads the package
  and puts the skill and the mod in `~/.claude/skills`, verifying the archive first. Done when: a buyer
  goes from the e-mail to `/security-audit` with one command, and the installer refuses a tampered archive.
- **R20 Buy from the terminal.** `npx @devince/apps buy security-audit` opens the checkout, waits for
  the payment and installs. Built product-agnostic: a product table plus an install manifest in the
  archive, so the next product reuses it unchanged. Done when: the flow works end to end on a test
  purchase and the CLI never trusts anything but the store's signed download token.

## Next

- **R04 Stack detection and `--stack`.** The report names the applied profile and what it does not cover;
  the flag forces a profile. Done when: Ledgerly, a PHP app and a Python app are detected correctly.
- **R05 PHP profile: Laravel, Symfony, Drupal.** Route-based entry points, unscoped Eloquent/Doctrine
  queries, `composer audit`, Psalm taint. Done when: its benchmark app scores.
- **R06 Python profile: Django, FastAPI, Flask.** Unscoped ORM queries, `bandit`, `pip-audit`.
  Done when: its benchmark app scores.
- **R07 Deterministic tools in the pre-pass.** semgrep rulesets per stack, `zizmor` for GitHub Actions,
  `hadolint` and `trivy` for Dockerfiles and images. Done when: each tool runs natively or via docker,
  reports NOT RUN honestly, and its hits appear as candidates in `prepass.md`.
- **R08 More checks.** CSRF, CI/CD (secrets in logs, `pull_request_target`, unpinned actions), Docker
  and IaC, supply chain (install scripts, lockfile integrity). Done when: each has checklist items and
  at least one seeded bug in a benchmark.

## Later

- **R09 Go profile** (`gosec`, error handling) and **R10 Rust profile** (`cargo-audit`, unsafe).
  Done when: their benchmark apps score.
- **R11 Export.** SARIF for GitHub code scanning; tasks to Linear and Jira with file, line and fix.
  Done when: one command produces the file or the tasks from `remediation.json`.
- **R12 Audit diff.** New, fixed and regressed findings between two runs, building on `--verify-fixes`.
  Done when: the report has a "since last audit" section.
- **R13 Cheaper auditors.** Measure on the benchmark whether auditors can run on a lighter model without
  losing recall. Done when: the number is published, whatever it says.
- **R14 Production checklist.** Generated from the not-assessed rows: headers, limits, env vars, backups,
  each with how to check it. Done when: it is a section of the report.

## Ideas

- **R15 Audit on every pull request**, headless, in CI.
- **R16 Ruby on Rails profile** (`brakeman`).
- **R17 audit-live:** phase timing, per-auditor view, token counter.
- **R18 Second private benchmark app**, never published, for measuring changes without training-data risk.

## Done

- **1.1.0** (2026-10-03): defensive finding format (impact and regression test instead of attack steps),
  `audit-live` mod, buyer guide with Discord.
- **1.0.0** (2026-10-02): pre-pass with hotspot ranking, `--scope`, sharded verification with COMBINE,
  HTML report, Ledgerly benchmark.

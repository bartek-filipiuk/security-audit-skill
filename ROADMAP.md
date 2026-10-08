# Roadmap

No dates. Four lanes, read left to right: Now, Next, Later, Ideas. Each item has a stable id
(R01…), one line on the value for the user and one line on the done criterion. The same list is on
https://security-audit.dev/roadmap; keep the two in sync. Contributions welcome: see AGENTS.md.

Rules that apply to every item:
- A stack profile ships only with its own benchmark app (seeded bugs and decoys), scored the same way as Ledgerly.
- Deterministic tool output is a candidate for the auditors, never a finding without verification in the code.
- Nothing in the skill describes or performs attacks: findings state the impact and carry a regression test.

## Now

- **R02 Supabase and Firebase profile.** RLS policies, storage policies, service-role keys in the client,
  Firestore rules. Done when: a benchmark app for this stack exists and the profile scores on it.

## Next

- **R05 PHP profile: Laravel, Symfony, Drupal.** Route-based entry points, unscoped Eloquent/Doctrine
  queries, `composer audit`, Psalm taint. Done when: its benchmark app scores.
- **R06 Python profile: Django, FastAPI, Flask.** Unscoped ORM queries, `bandit`, `pip-audit`.
  Done when: its benchmark app scores.
- **R07 Deterministic tools in the pre-pass.** semgrep rulesets per stack, `zizmor` for GitHub Actions,
  `hadolint` and `trivy` for Dockerfiles and images. Done when: each tool runs natively or via docker,
  reports NOT RUN honestly, and its hits appear as candidates in `prepass.md`.
- **R21 LLM and agent checks.** Prompt injection into tools and agents, model output reaching HTML, SQL,
  shell or URL sinks, tool calls without authorisation, cost and token abuse. Done when: checklist items,
  stack patterns and at least two seeded bugs in a benchmark app, scored.

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
- **R23 Resource exhaustion and spend.** Unbounded queries, uploads, queues and workers; paid APIs
  (SMS, e-mail, AI) that anonymous callers can drive. Done when: checklist items and a seeded bug, scored.
- **R24 Data lifecycle.** Tenant isolation in caches, search and exports; erasure that misses backups,
  files or derived data; restores that bring deleted people back. Done when: checklist items and a seeded
  bug, scored.
- **R25 Client-side checks.** DOM injection, `postMessage` trust, prototype pollution, UI redress.
  Done when: checklist items and a seeded bug in a benchmark app, scored.
- **R26 Any coding agent.** Install and run outside Claude Code (skills CLI), with the same report.
  Done when: the benchmark runs end to end in at least one other agent and the result is published.

## Ideas

- **R15 Audit on every pull request**, headless, in CI.
- **R16 Ruby on Rails profile** (`brakeman`).
- **R17 audit-live:** phase timing, per-auditor view, token counter.
- **R18 Second private benchmark app**, never published, for measuring changes without training-data risk.
- **R27 Native code and memory safety** (C, C++, unsafe Rust), **R28 mobile and local IPC** (deep links,
  webviews, exported components), **R29 protocols and RPC** (gRPC, queues, brokers, streaming). Wider scope
  than the web stack this skill is built for; each needs its own benchmark app before it ships.

## Done

- **R22 Coverage ledger** (2026-10-07): every auditor writes `coverage/<auditor>.json`, one row per entry point
  or project-wide check and class: `checked` with evidence, `not_applicable` or `not_assessed` with a reason.
  `scripts/coverage.mjs` validates it against `references/coverage-ledger.schema.json` (no dependencies) and
  `report.md` and `report.html` build their Coverage and Not Assessed sections from it, adding every class and
  pre-pass entry point with no row as "not looked at". `--since` carries the rows of untouched targets. Tests in
  `scripts/coverage.test.mjs`; the benchmark run is pending.

- **R08 More checks** (2026-10-06): checklist items and stack patterns for CSRF, CI/CD workflows
  (`pull_request_target`, expression injection, unpinned actions, secrets in logs), Docker and IaC, and
  supply chain (install scripts, lockfile integrity, unpinned sources). Ledgerly gained one seeded bug per
  area (B17 to B20) and three decoys (D09 to D11): 20 seeded bugs and 11 decoys. Recall from earlier runs is
  out of 16; the first scored run on the new key is the next benchmark round.

- **R04 Stack detection and `--stack`** (2026-10-05): the pre-pass detects each stack from its manifests
  (JS/TS, PHP, Python, Go, Rust, Ruby, JVM, .NET, with frameworks such as Next.js, Laravel, Django, FastAPI),
  and `prepass.md`, `report.md` and `report.html` name the applied profile, what it covers and what it does not;
  stacks without a dedicated profile say "general checklist". `--stack` forces a profile and warns on a
  conflict. Ledgerly, a Laravel fixture and Django/FastAPI fixtures are detected correctly (`scripts/stack.test.mjs`).

- **R03 Exact benchmark scoring** (2026-10-05): findings match the answer key by the file and line of their
  primary evidence (window of 2 lines, nearest entry wins), with no keyword fallback. Re-scoring the four R01
  runs kept recall 16/16 and 0 decoy false positives in each, and removed 21 to 29 loose finding-to-bug
  pairs per run (findings that had matched only through a cited context file and a keyword).

- **R01 Incremental audit, `--since <commit>|last`** (2026-10-04): re-audits the entry points whose code changed
  (directly or through imports) and carries the rest of the previous report, each item marked with its commit.
  On Ledgerly, a one-line change re-audited 4 of 47 targets for 4.70M tokens and 14.9 min against 11.57M and
  26.4 min for a full run (mean of two), recall 16/16 and no decoy false positive in all three runs.

- **Open source** (2026-10-03): MIT license, public repository, head-to-head with the Claude Security plugin
  in `benchmark/COMPARISON.md`. (R19 and R20 were the paid store's installer; retired with it.)

- **1.1.0** (2026-10-03): defensive finding format (impact and regression test instead of attack steps),
  `audit-live` mod, buyer guide with Discord.
- **1.0.0** (2026-10-02): pre-pass with hotspot ranking, `--scope`, sharded verification with COMBINE,
  HTML report, Ledgerly benchmark.

# Roadmap

No dates. Four lanes, read left to right: Now, Next, Later, Ideas. Each item has a stable id
(R01…), one line on the value for the user and one line on the done criterion. The same list is on
https://security-audit.dev/roadmap; keep the two in sync. Contributions welcome: see AGENTS.md.

Rules that apply to every item:
- A stack profile ships only with its own benchmark app (seeded bugs and decoys), scored the same way as Ledgerly.
- Deterministic tool output is a candidate for the auditors, never a finding without verification in the code.
- Nothing in the skill describes or performs attacks: findings state the impact and carry a regression test.

## Now

- **R32 Crypto and token API misuse.** Priority (2026-10-26): R31 showed the skill finds authorization and
  flow bugs (goshs 6/8) but misses crypto API misuse (fast-jwt 6.2.4: 1/3; missed a public JWK accepted as an
  HMAC secret and an empty key with an algorithm list accepting unsigned tokens). Checklist and verifier rules
  for key/algorithm confusion, empty or null keys, `alg` taken from the token, `none`, claim validation on
  non-object payloads, timing-unsafe compares, weak randomness for tokens, IV/nonce reuse; applies to apps
  and to libraries. Done when: fast-jwt 6.2.4 scores 3/3 on two runs, the 6.3.1 control stays at 0 decoy FP,
  and Ledgerly recall does not drop.
  Status (2026-10-26): code merged on branch, waiting for benchmark. Checklist 2.8 subsection "Token, signature
  and key APIs" (apps and library mode), crypto red-flag patterns, recon `Crypto-heavy` flag with
  `briefs.mjs --crypto-heavy` moving 2.8 to the Auth Auditor, verifier rule 6c for crypto and token defaults.

- **R05 PHP profile: Laravel, Symfony, Drupal.** Priority (2026-10-19): first in line for a scored run.
  Route-based entry points, unscoped Eloquent/Doctrine queries, `composer audit`, Psalm taint. Done when: its benchmark app scores.
  Status (2026-10-07): checklist sections, stack patterns, Laravel/Symfony entry points (Drupal's existed)
  ranked by their controller method, PHP template/model/CSRF signals, Psalm reported NOT RUN, and the
  `benchmark/php-tickets` app (13 seeded bugs, 14 decoys) are in; it moves to Done with its first scored run.
  Merged to main 2026-10-08 (#10 via #12). Its benchmark app is not scored yet; it moves to Done with its first
  scored run.
- **R02 Supabase and Firebase profile.** RLS policies, storage policies, service-role keys in the client,
  Firestore rules. Done when: a benchmark app for this stack exists and the profile scores on it.
  Status (2026-10-07): checklist sections, stack patterns, a pre-pass policy scan, Edge/Cloud Function entry
  points and the `benchmark/supabase-notes` app (10 seeded bugs, 12 decoys, `--app` in setup and score) are
  in; it moves to Done with its first scored run.
  Merged to main 2026-10-08 (#9 via #12). Its benchmark app is not scored yet; it moves to Done with its first
  scored run.
- **R23 Resource exhaustion and spend** (merged 2026-10-15 without a benchmark run yet, waiting for it). Unbounded queries, uploads,
  queues and workers; paid APIs (SMS, e-mail, AI) that anonymous callers can drive. Done when: checklist items
  and a seeded bug, scored.
  Status (2026-10-09): a checklist subsection under 2.3 (paid outbound calls, unbounded list queries, upload size
  and count, queues and jobs, expensive work and regex on input), stack patterns, a verifier regression-test rule,
  and Ledgerly B24 (anonymous sign-up route that sends a billed SMS to any number, no limit) with decoy D14 (an
  org-scoped, capped SMS reminder): 24 seeded bugs and 14 decoys. It moves to Done after a scored Ledgerly run
  (twice) shows no recall loss and no decoy false positive.
- **R24 Data lifecycle** (merged 2026-10-15 without a benchmark run yet, waiting for it). Tenant isolation in caches, search and exports;
  erasure that misses backups, files or derived data; restores that bring deleted people back. Done when:
  checklist items and a seeded bug, scored.
  Status (2026-10-10): a checklist subsection under 2.4 (cache keys, search and exports scoped to the tenant,
  complete erasure across related tables, stored objects, derived data and third parties, restores and imports
  that skip erased people, soft-delete on every read path), stack patterns, a verifier regression-test rule, and
  Ledgerly B25 (organization deletion that cascades the rows but leaves the uploaded objects in the bucket) with
  decoy D15 (a complete, org-scoped customer erasure): 25 seeded bugs and 15 decoys. Merged with R23 (#20). It
  moves to Done after a scored Ledgerly run (twice) shows no recall loss and no decoy false positive.
- **R25 Client-side checks** (merged 2026-10-15 without a benchmark run yet, waiting for it). DOM injection, `postMessage` trust,
  prototype pollution, UI redress. Done when: checklist items and a seeded bug in a benchmark app, scored.
  Status (2026-10-13): a checklist subsection under 2.2 (DOM sinks fed by untrusted data, `postMessage`
  receivers that check origin and source and senders that name the target, prototype pollution through
  user-controlled keys, frame protection for sensitive pages, client-side redirects, secrets in browser storage),
  stack patterns, a verifier regression-test rule, and Ledgerly B26 (a payment widget wrapper whose message
  listener checks no origin and navigates to a URL from the message) with decoy D16 (an e-signature frame with
  strict origin and source checks and schema validation): 26 seeded bugs and 16 decoys. Merged with R24 (#21).
  It moves to Done after a scored Ledgerly run (twice) shows no recall loss and no decoy false positive.
- **R15 Audit on every pull request**, headless, in CI. Done when: one recorded end-to-end run of the example
  workflow on a pull request.
  Status (2026-10-15): example workflow and scripts merged (`examples/github-actions/security-audit.yml`,
  `scripts/ci-scope.mjs`, `scripts/ci-summary.mjs`); moves to Done after one recorded end-to-end run.

## Next

- **R06 Python profile: Django, FastAPI, Flask.** Unscoped ORM queries, `bandit`, `pip-audit`.
  Done when: its benchmark app scores.
  Status (2026-10-08): checklist sections, stack patterns, Django (urls.py include chain, DRF routers and
  permission defaults), FastAPI (Depends on route, router, app and mount) and Flask (blueprints,
  `*_required`, `before_request`) entry points ranked by their view, a user-owned model scan, Python
  template/settings/CORS signals, bandit in the R07 tool runner (native only), `pip-audit` as a read-only dependency fallback,
  and the `benchmark/py-clinic` app (18 seeded bugs, 18 decoys) are in; it moves to Done with its first scored run.
  Merged to main 2026-10-08 (#11 via #12). Its benchmark app is not scored yet; it moves to Done with its first
  scored run.
- **R07 Deterministic tools in the pre-pass.** semgrep rulesets per stack, `zizmor` for GitHub Actions,
  `hadolint` and `trivy` for Dockerfiles and images. Done when: each tool runs natively or via docker,
  reports NOT RUN honestly, and its hits appear as candidates in `prepass.md`.
  Merged to main 2026-10-08 (#5 via #12). The tools were not installed on the benchmark host, so no real
  tool run is recorded yet.

## Later

- **R09 Go profile** (`gosec`, error handling) and **R10 Rust profile** (`cargo-audit`, unsafe).
  Done when: their benchmark apps score.
- **R13 Cheaper auditors.** Measure on the benchmark whether auditors can run on a lighter model without
  losing recall. Done when: the number is published, whatever it says.
- **R26 Any coding agent.** Install and run outside Claude Code (skills CLI), with the same report.
  (portability layer merged 2026-10-17, #24; end-to-end benchmark in OpenCode pending.) Done when: the benchmark runs end to end in at least one other agent and the result is published.

## Ideas

- **R30 Mini benchmarks on real advisories.** Small audits of real modules pinned to a version before a public
  security fix (for example a Drupal contrib module with a published advisory), scored on whether the skill
  finds the published issue. Defensive only: public advisories, no exploit code.
  Status (2026-10-19): tooling and keys in; first runs done (3.1.3: the CRITICAL SA-2026-031 found, 4 of 11
  advisories by hand; 3.2.0 control: no fixed advisory reported again). Results in `benchmark/real/README.md`. `benchmark/real/fetch.mjs` (pinned sha256,
  `--check`), `score.mjs --key`, and keys for the Drupal module `miniorange_saml` 3.1.3 (11 drupal.org advisories)
  with 3.2.0 as the fixed control.
  Fix from the first run (2026-10-21, SEC-21, waits for a benchmark run): the verifier never rejects an
  unauthenticated config or admin write as best practice; only a cited control does.
  SEC-22 (2026-10-21, waits for a benchmark run): a SAML/SSO service-provider subsection under checklist 2.1 and its
  stack patterns (algorithm allow-list, signature failure stops login, replay, configured cert, metadata fetch, debug ACS).
- **R31 Weekly real-advisory dataset.** Extends R30 with a few public modules a week across ecosystems
  (Drupal, WordPress, npm, PyPI, RubyGems, Go), each pinned to a release before a recent advisory and scored
  against its fixed release as the control. Unmatched findings are never published; the owner verifies them
  and reports privately (policy in `benchmark/real/README.md`).
  Status (2026-10-20): tooling and week-1 keys in; runs pending the owner's budget. `fetch.mjs` takes
  `ecosystem/package` ids, zip and gem archives with entry checks, and an explicit module root; week 1 is
  `drupal/rest_api_authentication` 3.1.0, `wordpress/flamingo` 2.6.2, `npm/fast-jwt` 6.2.4 (3 advisories)
  and `go/goshs` v2.1.4 (8 advisories).
- **R16 Ruby on Rails profile** (`brakeman`).
- **R18 Second private benchmark app**, never published, for measuring changes without training-data risk.
- **R27 Native code and memory safety** (C, C++, unsafe Rust), **R28 mobile and local IPC** (deep links,
  webviews, exported components), **R29 protocols and RPC** (gRPC, queues, brokers, streaming). Wider scope
  than the web stack this skill is built for; each needs its own benchmark app before it ships.

## Done

- **R17 audit-live: phase timing, per-auditor view, session cost** (2026-10-15): the optional mod's pane shows
  how long each phase took and how long the current one has run, derived from the mtimes of the files each phase
  writes (`prepass.md`, `recon.md`, the newest writer ledger in `coverage/`, the newest verified or rejected
  finding, `test-quality.md`, `report.html`) and the run start in `tools/workspace-mark.json`; a phase whose end
  cannot be told shows "—". An Auditors section lists each `auditor-<name>` with its open findings by severity
  (from `source_agent`), its ledger rows (checked, not applicable, not assessed) and done or running. A dim
  line shows Claude Code's own session cost and context use from `$.session.usage`, left out when Claude Code
  does not answer it; it is not the subagent sum of `benchmark/usage.mjs`. The frontmatter parser now keeps
  digits and hyphens in values. Mod-only: no change to the skill, its prompts or scripts, so no benchmark run.
- **R14 Production checklist** (2026-10-09): `report.md` and `report.html` have a "Production checklist" section
  after Not Assessed. `scripts/prod-checklist.mjs` holds a small catalogue (headers, TLS, limits, env vars and debug
  flags, secrets, backups, logging, dependency updates, exposed ports, cookies), each with a read-only "how to
  check"; an item is marked "from this audit" when a Not Assessed row matches it (the row is named), the rest are
  baseline. No model work. Tests in `scripts/prod-checklist.test.mjs`; it does not change the audit, so no benchmark run.

- **R12 Audit diff** (2026-10-09): `report.md` and `report.html` have a "Since last audit" section from the second
  run on. `scripts/diff.mjs` compares the verified findings with the newest finished run in `history/` (archived
  whole by `prepass --new-run`, remediation blocks included, so `--verify-fixes` state counts): new, fixed (gone
  from a full audit, or marked fixed), regressed (marked fixed before, or gone from the previous full run and back),
  unchanged, severity changes, and "not re-checked" for a partial run. Findings match by category + file + line
  ranges within 3 lines, then category + file + normalized title, then category + title (moved file). No model
  work. Tests in `scripts/diff.test.mjs`; it does not change what the audit finds, so no benchmark run.

- **R11 Export** (2026-10-08): `node scripts/export.mjs --format sarif|linear|jira` turns `remediation.json` and
  the finding files into SARIF 2.1.0 for GitHub code scanning (one rule per finding with the fix as help, level
  from severity, file and line) or a CSV for Linear or Jira import (title, description with file:line, impact
  and fix, priority, labels). No network calls and no tokens: the user uploads or imports the file. Fixed and
  accepted findings are left out unless `--all`. Tests in `scripts/export.test.mjs`; it does not change the audit,
  so no benchmark run.

- **R21 LLM and agent checks** (2026-10-08, #7 via #12): checklist items and stack patterns for prompt injection
  into tools and agents, model output reaching HTML/SQL/shell/URL sinks, tool calls without authorisation and
  cost/token abuse; three seeded Ledgerly bugs (B21-B23). Benchmark 2026-10-08 (batch #12, Ledgerly x1): recall 20/23, 0 decoy false positives.
  B21 and B22 found exactly; B23 was found but cited at the route signature, outside the key window.

- **R22 Coverage ledger** (2026-10-07): every auditor writes `coverage/<auditor>.json`, one row per entry point
  or project-wide check and class: `checked` with evidence, `not_applicable` or `not_assessed` with a reason.
  `scripts/coverage.mjs` validates it against `references/coverage-ledger.schema.json` (no dependencies) and
  `report.md` and `report.html` build their Coverage and Not Assessed sections from it, adding every class and
  pre-pass entry point with no row as "not looked at". `--since` carries the rows of untouched targets. Tests in
  `scripts/coverage.test.mjs`; the benchmark run is pending.
  Benchmark 2026-10-08 (batch #12, Ledgerly x1): recall 20/23, 0 decoy false positives.

- **R08 More checks** (2026-10-06): checklist items and stack patterns for CSRF, CI/CD workflows
  (`pull_request_target`, expression injection, unpinned actions, secrets in logs), Docker and IaC, and
  supply chain (install scripts, lockfile integrity, unpinned sources). Ledgerly gained one seeded bug per
  area (B17 to B20) and three decoys (D09 to D11): 20 seeded bugs and 11 decoys. Recall from earlier runs is
  out of 16; the first scored run on the new key is the next benchmark round.
  Benchmark 2026-10-08 (batch #12, Ledgerly x1): recall 20/23, 0 decoy false positives.

- **R04 Stack detection and `--stack`** (2026-10-05): the pre-pass detects each stack from its manifests
  (JS/TS, PHP, Python, Go, Rust, Ruby, JVM, .NET, with frameworks such as Next.js, Laravel, Django, FastAPI),
  and `prepass.md`, `report.md` and `report.html` name the applied profile, what it covers and what it does not;
  stacks without a dedicated profile say "general checklist". `--stack` forces a profile and warns on a
  conflict. Ledgerly, a Laravel fixture and Django/FastAPI fixtures are detected correctly (`scripts/stack.test.mjs`).
  Benchmark 2026-10-08 (batch #12, Ledgerly x1): recall 20/23, 0 decoy false positives.

- **R03 Exact benchmark scoring** (2026-10-05): findings match the answer key by the file and line of their
  primary evidence (window of 2 lines, nearest entry wins), with no keyword fallback. Re-scoring the four R01
  runs kept recall 16/16 and 0 decoy false positives in each, and removed 21 to 29 loose finding-to-bug
  pairs per run (findings that had matched only through a cited context file and a keyword).
  Since 2026-10-20 a finding whose primary location matches nothing may match one entry through its
  secondary locations (the rest of its `**File**:` line, or the Evidence of a systematic finding); decoys
  count only through the primary (`benchmark/README.md`, Rules).

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

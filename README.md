# security-audit

A Claude Code skill that audits the security of your own code and hands back a report: what to fix, what is
verified safe (with the control's file:line) and what could not be checked. Open source, MIT.

Project page: https://security-audit.dev

## Install

```bash
git clone https://github.com/bartek-filipiuk/security-audit-skill ~/.claude/skills/security-audit
```

Update with `git -C ~/.claude/skills/security-audit pull`. Check the scripts (seconds, no tokens):
`cd ~/.claude/skills/security-audit && node --test scripts/`.

Requirements: Claude Code, Node 20+. For dependency and secret scanning, either `osv-scanner` and `gitleaks` on
`PATH` or a running docker daemon; without them the report lists those two checks as not run. Optional rule
scanners, used when the project has something for them: `semgrep` (code), `zizmor` (GitHub Actions), `hadolint`
(Dockerfiles), `trivy` (Dockerfiles and IaC). Install them (`pipx install semgrep zizmor`, `brew install hadolint
trivy`) or run docker, and the pre-pass uses their official images pinned by digest. Each one that applies but
cannot run is listed as not assessed. Tested on Linux.

Optional live progress panel (a Claude Code mod, 2.1.287+): `cp -r ~/.claude/skills/security-audit/audit-live
~/.claude/skills/`. It only reads `.security-audit/`; see `audit-live/README.md`.

## Use

In your project, in Claude Code:

```
/security-audit                     # whole project
/security-audit --scope top20       # the 20 riskiest places, a cheap first run
/security-audit --scope auth        # areas: auth, admin, payments, webhooks, files, ai, jobs, api
/security-audit --scope src/app/api # a path
/security-audit --verify-fixes      # recompute what is fixed, change nothing
/security-audit --since last        # re-audit only what changed since the last audit
/security-audit --since <commit>    # ... or since a commit; the rest of the report is carried over
/security-audit --stack laravel     # force a profile instead of the detected one (js, php, python, go, ...)
```

The pre-pass detects the stack from the manifests (package.json, composer.json, pyproject.toml or
requirements.txt, go.mod, Cargo.toml, Gemfile, pom.xml, ...) and the report names the applied profile, what it
covers and what it does not. Only JavaScript/TypeScript (Node) has a dedicated profile today; PHP, Python and
the rest run on the general checklist, and the report says so. In a monorepo every detected stack gets its own
profile line, with the directories it was found in. `--stack` applies one profile instead and warns when it
does not match the code.

`--since` audits the entry points whose code changed (directly or through an imported file) and copies the
previous run's findings and verified-safe items that cite no changed file, each marked with the commit it was
read at. Without a usable previous full audit, or when a file that gates every route changed, it runs a full
audit and says why.

Install the project's dependencies first, so the regression tests the audit writes can run. The report is
`.security-audit/report.html`; the directory is gitignored because it names unfixed weaknesses.

Cost: a full run on the benchmark app (45 entry points) took 32 minutes and 23.8M tokens, about 11.70 USD at
API prices (Opus 5.5, effort xhigh); a 160-entry-point project took 2 h 11 min. Start big projects with
`--scope top20`. Re-auditing a one-line change with `--since` cost 4.7M tokens and 15 minutes on the same app
(a headless full run there: 11.6M and 26 minutes).

## How it compares

Anthropic's free [Claude Security plugin](https://code.claude.com/docs/en/claude-security) does a similar
multi-agent scan. On the benchmark app as it was then (16 seeded bugs, before R08 added four) both found them (16 of 16 here, 15 of 16 for the plugin) with
no decoy false positives; the plugin was faster. This skill adds dependency advisories (osv-scanner), secrets in
the whole git history (gitleaks), regression tests that fail today as proof, a verified-safe list, a
not-assessed list and a review of the project's tests. The plugin adds SARIF, branch-diff scans and reviewed
patches. Use both. Details and caveats: [benchmark/COMPARISON.md](benchmark/COMPARISON.md).

## How it works

A deterministic pre-pass (seconds) followed by a 5-phase agent pipeline (Recon → Parallel Audit → Deep Dive Verification → Test Quality → Report Assembly), with 3 operating modes based on project size:

| Entry points | Mode | Agents |
|---|---|---|
| < 20 | Standard | 1 agent, sequential |
| 20-50 | Triage | 1 agent, prioritized (HIGH→LOW) |
| 50+ | Parallel | 3-5 parallel auditors (≈8 agents across the full pipeline) |

### Pipeline (Parallel Mode)

```
prepass.mjs (no LLM) → entry points by framework convention, Drizzle scope scan,
                       osv-scanner advisories, gitleaks over git history,
                       semgrep / zizmor / hadolint / trivy candidates → prepass.md
        ↓
Recon Scanner (Sonnet) → maps exposed surface + authorization map, writes .security-audit/recon.md
        ↓
Category Auditors (Sonnet, parallel) → audit by domain, write findings/
        ↓
Deep Dive Verifier (session model) → verify, expand, chain, prove HIGH/CRITICAL, reject false positives
        ↓
Test Quality Auditor (Sonnet) → assess test coverage vs findings
        ↓
Coordinator → assembles final report.md, audit-state.mjs generates remediation.json
```

### Shared knowledge

All agents communicate via `.security-audit/` directory:

```
.security-audit/
├── prepass.md        # Deterministic pre-pass output
├── tools/            # Raw scanner output (secrets redacted)
├── recon.md          # Exposed surface + authorization map
├── findings/         # One file per finding (raw → verified/rejected)
├── non-issues/       # Areas examined and found secure (with the control's file:line)
├── not-assessed.md   # Coverage gaps
├── tests/            # Regression tests for HIGH/CRITICAL
├── test-quality.md   # Test coverage assessment
├── report.md         # Final report
└── remediation.json  # Generated from finding frontmatter
```

The directory is added to `.gitignore` before anything is written: it names unfixed weaknesses with file and line.

## Structure

```
SKILL.md                          # Main skill — coordinator workflow
agents/
  recon-scanner.md                # Phase 1: map exposed surface
  category-auditor.md             # Phase 2: audit by category (parallel)
  deep-dive-verifier.md           # Phase 3: verify, expand, chain findings
  test-quality-auditor.md         # Phase 4: assess test quality
references/
  audit-checklist.md              # 12-category security checklist
  finding-format.md               # Structured formats for all output files
  report-template.md              # Final report markdown template
  stack-patterns.md               # Grep patterns per language/framework
  remediation.md                  # Phase 6 fixes + remediation.json contract
scripts/
  prepass.mjs                     # Phase 0: deterministic pre-pass (node, no deps; docker for scanners)
  surface.mjs                     # Entry point enumeration + Drizzle scope scan
  stack.mjs                       # Stack detection from manifests, profiles, --stack
  tools.mjs                       # semgrep, zizmor, hadolint, trivy: detect, run, normalize candidates
  incremental.mjs                 # --since: changed files -> re-audit targets, carried findings
  audit-state.mjs                 # Validates findings, generates remediation.json
  report-html.mjs                 # Renders report.html: to fix / verified safe / not assessed
  report-md.mjs                   # Assembles report.md from the coordinator's summary.md + audit files
  briefs.mjs                      # Per-auditor briefs (checklist sections + patterns for the repo's languages)
  workspace-check.mjs             # What changed in the project while the audit ran
  selftest.test.mjs               # node --test scripts/
benchmark/
  app/                            # Ledgerly: seeded-bug app in the target stack
  answer-key.json                 # Ground truth (never copied into the audited dir)
  setup.mjs, score.mjs            # Create a run, score it (also Claude Security output); results.jsonl keeps history
  usage.mjs                       # Tokens and API-price cost of a session, subagents included
  COMPARISON.md                   # Head-to-head with the Claude Security plugin
```

Requirements: Node 20+. For dependency and secret scanning, either `osv-scanner` and `gitleaks` on PATH or a running docker daemon (official images are pulled on first use). The rule scanners `semgrep`, `zizmor`, `hadolint` and `trivy` are optional the same way: native binary first, then the official image pinned by digest. Without them the pre-pass says NOT RUN with how to enable it and the report lists the gap. Their hits are candidates for the auditors, never findings.

## Key features

- **Evidence-based**: every finding requires file:line, code snippet, and an Impact section (who can do what they should not)
- **Deterministic first**: entry points, tenant-scope candidates, CVEs and secrets in git history come from scripts and scanners, not from model memory
- **Anti-hallucination**: 12 hard rules + mandatory 4-part REJECT gate (evidence, reachability, direction, dedup); no "secure" without the control's file:line
- **Proof labels**: every HIGH/CRITICAL is marked `test` (a regression test fails today) or `static` (code reading only)
- **Measurement-driven**: Deep Dive iterates (max 3) and stops on set-convergence (no new findings / status changes / chains); score is a reporting metric
- **Separate verification**: a different agent re-reads the code for every finding and rejects what it cannot confirm
- **Cross-domain chain detection**: verifier sees findings from ALL auditors, detects multi-step chains
- **Stack-aware**: most precise on Next.js App Router, tRPC, Hono, Drizzle, Better-Auth, AI SDK and plain Node; other languages run on general rules
- **Persistent**: findings survive sessions — resume, re-run, extend anytime
- **Hotspots first**: the pre-pass ranks entry points and auth/CORS/env config by risk signals; auditors start there
- **Measured**: a seeded-bug benchmark (`benchmark/`) scores recall, verifier drops and decoy false positives per change

## Audit categories

1. Authentication & Authorization
2. Input Validation & Injection (SQL, XSS, SSTI, prototype pollution, NoSQL, LDAP, host header, second-order...)
3. Rate Limiting & Abuse Prevention
4. Data Exposure
5. Security Headers & Transport
6. File Upload
7. Dependency Security
8. Cryptography (including JWT algorithm confusion)
9. Concurrency & Race Conditions
10. Documentation vs Reality
11. Business Logic
12. Logging & Monitoring

## Roadmap, contributing, security

- [ROADMAP.md](ROADMAP.md): stack profiles (PHP, Python, Go, Rust), branch-diff audits, SARIF, a second benchmark.
- [AGENTS.md](AGENTS.md): how to contribute (people and agents): rules, benchmark before and after, tests.
- [SECURITY.md](SECURITY.md): report a weakness in the skill itself privately.

The skill is a code review tool, not a guarantee and not a pentest. No findings does not mean no
vulnerabilities; that is why the report has a not-assessed list.

License: MIT.

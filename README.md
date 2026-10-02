# security-audit-skill

Claude Code skill for evidence-based, multi-agent security auditing of any codebase.

## Installation

Copy or symlink to your Claude Code skills directory:

```bash
# Copy
cp -r . ~/.claude/skills/security-audit/

# Or symlink
ln -s "$(pwd)" ~/.claude/skills/security-audit
```

## Usage

In any project, ask Claude Code:

```
/security-audit
```

or naturally:

```
zrób security audit tego projektu
audit this project for security issues
find vulnerabilities in this codebase
```

Partial audits: `/security-audit --scope auth` (areas: auth, admin, payments, webhooks, files, ai, jobs, api), `--scope src/app/api` (a path), or `--scope top20` (the 20 riskiest hotspots). The pre-pass ranks hotspots on every run; scoped runs say so in the report.

A full Parallel run is expensive: on a 161-entry-point project it took about 2 h and 4.8M subagent tokens (see "Cost on Big Projects" in SKILL.md). Start big projects with `--scope top20` or one domain.

At the end, `.security-audit/report.html` shows what to fix (red), what is verified safe with evidence (green) and what was not assessed (grey). It contains exploit steps and stays private.

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
                       osv-scanner advisories, gitleaks over git history → prepass.md
        ↓
Recon Scanner (Sonnet) → maps attack surface + authorization map, writes .security-audit/recon.md
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
├── recon.md          # Attack surface + authorization map
├── findings/         # One file per finding (raw → verified/rejected)
├── non-issues/       # Areas examined and found secure (with the control's file:line)
├── not-assessed.md   # Coverage gaps
├── poc/              # Proofs of concept for HIGH/CRITICAL
├── test-quality.md   # Test coverage assessment
├── report.md         # Final report
└── remediation.json  # Generated from finding frontmatter
```

The directory is added to `.gitignore` before anything is written: it contains working exploit steps.

```
```

## Structure

```
SKILL.md                          # Main skill — coordinator workflow
agents/
  recon-scanner.md                # Phase 1: map attack surface
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
  audit-state.mjs                 # Validates findings, generates remediation.json
  report-html.mjs                 # Renders report.html: to fix / verified safe / not assessed
  report-md.mjs                   # Assembles report.md from the coordinator's summary.md + audit files
  briefs.mjs                      # Per-auditor briefs (checklist sections + patterns for the repo's languages)
  workspace-check.mjs             # What changed in the project while the audit ran
  selftest.test.mjs               # node --test scripts/
benchmark/
  app/                            # Ledgerly: private seeded-bug app in the target stack
  answer-key.json                 # Ground truth (never copied into the audited dir)
  setup.mjs, score.mjs            # Create a run, score it; results.jsonl keeps history
```

Requirements: Node 20+. For dependency and secret scanning, either `osv-scanner` and `gitleaks` on PATH or a running docker daemon (official images are pulled on first use). Without them the pre-pass says NOT RUN and the report lists the gap.

## Key features

- **Evidence-based**: every finding requires file:line, code snippet, and numbered exploit steps
- **Deterministic first**: entry points, tenant-scope candidates, CVEs and secrets in git history come from scripts and scanners, not from model memory
- **Anti-hallucination**: 12 hard rules + mandatory 4-part REJECT gate (evidence, reachability, direction, dedup); no "secure" without the control's file:line
- **Proof labels**: every HIGH/CRITICAL is marked `dynamic` (exploit run locally) or `static` (code reading only)
- **Measurement-driven**: Deep Dive iterates (max 3) and stops on set-convergence (no new findings / status changes / chains); score is a reporting metric
- **Separate verification**: different agent verifies findings (79% false positive reduction pattern)
- **Cross-domain chain detection**: verifier sees findings from ALL auditors, detects multi-step exploits
- **Stack-agnostic**: auto-detects language/framework, adapts checklist and patterns
- **Persistent**: findings survive sessions — resume, re-run, extend anytime
- **Hotspots first**: the pre-pass ranks entry points and auth/CORS/env config by risk signals; auditors start there
- **Measured**: a private seeded-bug benchmark (`benchmark/`) scores recall, verifier drops and decoy false positives per skill change

## Audit categories

1. Authentication & Authorization
2. Input Validation & Injection (SQL, XSS, SSTI, prototype pollution, NoSQL, LDAP, host header, second-order...)
3. Rate Limiting & Abuse Prevention
4. Data Exposure
5. Security Headers & Transport
6. File Upload
7. Dependency Security
8. Cryptography (including JWT algorithm attacks)
9. Concurrency & Race Conditions
10. Documentation vs Reality
11. Business Logic
12. Logging & Monitoring

## Roadmap and live progress

- [ROADMAP.md](ROADMAP.md): stack profiles (PHP, Python, Go, Rust), stack detection and the `--stack` flag.
- [audit-live/](audit-live/): an optional Claude Code mod that shows the audit's progress live. Copy that folder to `~/.claude/skills/audit-live`.

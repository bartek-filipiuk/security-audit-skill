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

## How it works

4-phase pipeline with 3 operating modes based on project size:

| Entry points | Mode | Agents |
|---|---|---|
| < 20 | Standard | 1 agent, sequential |
| 20-50 | Triage | 1 agent, prioritized (HIGH→LOW) |
| 50+ | Parallel | 5-8 agents, multi-agent pipeline |

### Pipeline (Parallel Mode)

```
Recon Scanner (Sonnet) → maps attack surface, writes .security-audit/recon.md
        ↓
Category Auditors (Sonnet, parallel) → audit by domain, write findings/
        ↓
Deep Dive Verifier (Opus) → verify, expand, chain, reject false positives
        ↓
Test Quality Auditor (Sonnet) → assess test coverage vs findings
        ↓
Coordinator → assembles final report.md
```

### Shared knowledge

All agents communicate via `.security-audit/` directory:

```
.security-audit/
├── recon.md          # Attack surface map
├── findings/         # One file per finding (raw → verified/rejected)
├── non-issues/       # Areas examined and found secure
├── test-quality.md   # Test coverage assessment
└── report.md         # Final report
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
```

## Key features

- **Evidence-based**: every finding requires file:line, code snippet, and numbered exploit steps
- **Anti-hallucination**: 7 hard rules + mandatory REJECT gate (5-part checklist)
- **Measurement-driven**: scoring metric controls Deep Dive iteration (max 3, stop on delta=0)
- **Separate verification**: different agent verifies findings (79% false positive reduction pattern)
- **Cross-domain chain detection**: verifier sees findings from ALL auditors, detects multi-step exploits
- **Stack-agnostic**: auto-detects language/framework, adapts checklist and patterns
- **Persistent**: findings survive sessions — resume, re-run, extend anytime

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

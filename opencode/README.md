# security-audit for OpenCode

The OpenCode variant of the security-audit skill: the same pipeline, prompts, checklist and scripts as the
Claude Code skill, packaged as OpenCode agents. It does not need the Claude Code variant and does not touch it.

Requirements: OpenCode 2.1+, Node 20+. For dependency and secret scanning, `osv-scanner` and `gitleaks` on
`PATH` or a running docker daemon; without them the report lists those checks as not run.

## Install

From the built package (`dist/opencode/` in the repository, or the release archive):

```bash
node install.mjs --auditor-model <provider/model> --verifier-model <provider/model>
```

The installer writes into `~/.config/opencode/`: five agents (`sa-coordinator`, `sa-recon`, `sa-auditor`,
`sa-verifier`, `sa-test-quality`), the `/security-audit` command, a redirect skill, the guard plugin
`plugins/security-audit-guard.js` and the scripts and references in `security-audit/`. It also denies the skill
named `security-audit` in `opencode.json` (backup in `opencode.json.bak`), because OpenCode reads
`~/.claude/skills` and would otherwise load the Claude Code variant with instructions it cannot follow.

Models: the auditors find candidates, the verifier rejects or confirms them. Give the verifier the strongest
model you have, ideally from a different vendor than the auditors, so the two phases do not share blind
spots. A model counts as supported only after it scores on the Ledgerly benchmark like the Claude variant.

**Your code goes to the model providers you choose.** Free or trial models may keep or train on what they
receive. Do not audit code you are not allowed to share with that provider.

## Use

```
/security-audit                     # whole project
/security-audit --scope top20       # the 20 riskiest places, a cheap first run
/security-audit --scope auth        # areas: auth, admin, payments, webhooks, files, ai, jobs, api
/security-audit --since last        # re-audit only what changed since the last audit
/security-audit --stack python      # force a stack profile
/security-audit --verify-fixes      # recompute what is fixed, change nothing
```

Headless: `opencode run --agent sa-coordinator "Arguments: --scope top20"` (a message starting with `--` is
read as a flag). Start it in the project directory: OpenCode takes the project from `$PWD`, so a script that
only changes the child's working directory must set `PWD` too. The report is `.security-audit/report.html`.

## What is enforced

The Claude Code variant states its rules in the prompt. Here they are agent permissions as well:

- edits only inside `.security-audit/` (the coordinator also `.gitignore`); no `.env` reads; no web access;
- shell is deny-by-default: the skill's scripts, read-only git, `ls`, and the project's test runner;
- the guard plugin refuses shell redirection or `git --output` outside `.security-audit/`, and refuses to render
  the report while `audit-state.mjs --final` fails.

The limit: the test runner executes the regression tests the verifier writes, and test code can do anything
the project's tests can. The permissions stop accidents, not a hostile model. `workspace-check.mjs` lists any
file changed outside `.security-audit/` at the end of the run.

## Differences from the Claude Code variant

- No Phase 6 (fixing): no audit agent may edit source. Fix in a normal session, then `--verify-fixes`.
- No `--mutation`: it needs a copy of the repository outside the project.
- No audit-live panel.

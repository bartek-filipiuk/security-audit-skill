# Contributing to security-audit

For anyone who changes this repository, person or agent. Read it before the first pull request.

## Layout

`SKILL.md` (the pipeline), `agents/` (prompts of the sub-agents), `references/` (checklist, formats, stack
patterns), `scripts/` (deterministic pre-pass, state validation, report rendering), `benchmark/` (Ledgerly,
a test app with 23 seeded bugs and 13 decoys, plus the scorer and the usage counter), `audit-live/`
(optional Claude Code mod), `ROADMAP.md` (the plan, ids R01…).

## Rules

1. **Defensive by construction.** The skill describes impact and writes regression tests. It never writes
   attack steps, exploit scripts, network tooling or anything that works against another host. Keep that
   in prompts, references, scripts and report wording. If a change needs attack-style content to work, the
   change is wrong.
2. **No reassurance without evidence.** A non-issue cites the file:line of the control. A tool that did not
   run is a gap in `not-assessed.md`, never silence.
3. **Measure before and after.** Every change to prompts, scripts, models or speed is measured on the
   benchmark: `node benchmark/setup.mjs --dest <dir>`, a fresh Claude Code session in `<dir>/app`,
   `/security-audit`, then `node benchmark/score.mjs <dir> --label "<change>"` and
   `node benchmark/usage.mjs <session id>`. Paste both outputs into the pull request. Run twice before
   trusting a difference of one or two bugs. A change that lowers recall or adds a decoy false positive does
   not merge, whatever else it improves.
4. **Scripts have tests.** `node --test scripts/` must pass; the mod: `cd audit-live && claude plugin
   validate . && claude plugin test`. Add a test for every new script behaviour.
5. **No real projects.** No names, paths, findings or numbers from anyone's real project in the repo.
   Ledgerly and the other benchmark apps under `benchmark/` are the only projects that may be named. Never commit `.security-audit/` output or `.env` files.

## Stack profiles

A profile (roadmap R02, R05, R06, R09, R10, R16) is: entry-point detection in `scripts/surface.mjs`, hotspot
signals, patterns in `references/stack-patterns.md`, checklist items, deterministic scanners wired into
`scripts/prepass.mjs` with honest NOT RUN handling, and its own benchmark app under `benchmark/<name>/` with
an answer key in the Ledgerly format. It ships only when the scorer runs on that app.

Deterministic tools run natively if installed, else through their official docker image pinned by digest,
else report NOT RUN with how to enable them. Their output is a candidate for the auditors; the tool never
writes a finding.

## Pull requests

One roadmap item or one fix per pull request, small commits in English, the benchmark lines and test output
in the description. Releases are tagged on `main` by the maintainer.

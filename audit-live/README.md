# audit-live

A Claude Code mod that shows live progress of the `security-audit` skill: the current phase and how
long each phase took, findings by severity and by auditor, a notice for each new finding, a notice when
the report is ready, and the session's cost as Claude Code counts it.
Optional. The skill works the same without it.

Tested with Claude Code 2.1.288. Phase timing, auditors and session cost pass `claude plugin test` on 2.1.296. Mods need 2.1.287 or later.

## What it does

- A pane named "Audit": phase, counts by severity, confirmed / unverified / filtered out, verified safe, not assessed, latest findings.
- Phases: how long each finished phase took and how long the current one has been running, plus the total.
  The run starts at `tools/workspace-mark.json`; a phase ends at the last write of its file: `prepass.md`,
  `recon.md`, the newest ledger in `coverage/` (`auditor-*.json`, `coordinator.json`), the newest finding the
  verifier marked verified or rejected, `test-quality.md`, `report.html`. These are file times, so they are
  approximate: a phase whose end cannot be told (or whose file was rewritten later) shows "—". In Standard
  mode one agent writes `coordinator.json` as it goes, so the Audit and Verification split is rough.
- Auditors: one row per `auditor-<name>` with its open findings by severity (from the finding's
  `source_agent`), and once its ledger `coverage/auditor-<name>.json` exists, "done" and the ledger rows
  checked / n/a / not assessed. With findings but no ledger yet it shows "running". `coverage/carried.json`
  (rows carried from an earlier run) is ignored. Standard mode has no auditors, so the section stays empty.
- Session cost: `Session (Claude Code): $1.23 · context 42%`, read from Claude Code's `$.session.usage`
  every 15 seconds. This is Claude Code's own figure for the current session, not the per-run sum of
  subagent transcripts that `benchmark/usage.mjs` prints, and it is not verified whether it includes the
  audit's subagents. When Claude Code does not answer the call, the line is left out.
- A toast for each new finding and one when `report.html` is written.
- A short suffix beside the spinner while the audit runs, for example `audit: Verification · 2 critical · 5 high`.
- `/audit-live` opens the pane and prints a one-line summary (phase, total time, counts, session cost).

In a project without a `.security-audit/` directory it shows nothing.

## What it can reach

A mod runs with your permissions, so read `hooks/register.js` before you load it (about 360 lines).
It lists and reads files under `.security-audit/` in the working directory (`$.fs.list` also gives each
file's size and modification time, which the phase timing uses), reads the clock, and asks Claude Code
for the session's cost and context figure (`$.session.usage`). It reads no transcript and nothing outside
`.security-audit/`, writes nothing, starts no process and makes no network request.
`claude plugin validate .` lists every call it makes.

## Install

Copy this folder to `~/.claude/skills/audit-live`:

    cp -r audit-live ~/.claude/skills/

Claude Code then loads it in every session. Check with `claude plugin list`: it shows
`audit-live@skills-dir` as loaded. To remove it, delete that folder.

To try it for one session without installing: `claude --plugin-dir /path/to/audit-live`.

## Use

Run `/security-audit` as usual. The Audit pane opens by itself in a terminal at least 144 columns
wide once the audit writes something during the session, so an old audit left in the project stays
quiet. In a narrower terminal, or to look at an old audit, type `/audit-live`. Esc closes the pane.

## Try it without an audit

`node demo.mjs` writes a fake audit step by step into a temporary directory, so you can watch the pane fill in.

## Develop

    claude plugin validate .
    claude plugin test

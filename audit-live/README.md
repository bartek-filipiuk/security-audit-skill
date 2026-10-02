# audit-live

A Claude Code mod that shows live progress of the `security-audit` skill: the current phase,
findings by severity, a notice for each new finding and a notice when the report is ready.
Optional. The skill works the same without it.

Tested with Claude Code 2.1.288. Mods need 2.1.287 or later.

## What it does

- A pane named "Audit": phase, counts by severity, confirmed / unverified / filtered out, verified safe, not assessed, latest findings.
- A toast for each new finding and one when `report.html` is written.
- A short suffix beside the spinner while the audit runs, for example `audit: Verification · 2 critical · 5 high`.
- `/audit-live` opens the pane and prints a one-line summary.

In a project without a `.security-audit/` directory it shows nothing.

## What it can reach

A mod runs with your permissions, so read `hooks/register.js` before you load it (about 170 lines).
It lists and reads files under `.security-audit/` in the working directory. It writes nothing, starts
no process and makes no network request. `claude plugin validate .` lists every call it makes.

## Install

Copy this folder to `~/.claude/skills/audit-live`:

    cp -r audit-live ~/.claude/skills/

Claude Code then loads it in every session. Check with `claude plugin list`: it shows
`audit-live@skills-dir` as loaded. To remove it, delete that folder.

To try it for one session without installing: `claude --plugin-dir /path/to/audit-live`.

## Use

Run `/security-audit` as usual. The Audit pane opens by itself in a terminal at least 144 columns
wide; in a narrower one, type `/audit-live`.

## Try it without an audit

`node demo.mjs` writes a fake audit step by step into a temporary directory, so you can watch the pane fill in.

## Develop

    claude plugin validate .
    claude plugin test

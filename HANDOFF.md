# Handoff for the agent taking over development

Start here, in this order:

1. Read `AGENTS.md` (rules, workflow, release) and `ROADMAP.md` (what and why, ids R01…).
2. Tasks: devince-crm, project **SEC** (crm.devince.dev). One task per roadmap item, `SEC-1` = R01 …
   `SEC-18` = R18, grouped in epics Teraz / Następne / Później / Pomysły. Dependencies are set:
   the stack profiles and the deterministic tools are blocked by R04 (stack detection); the audit diff
   (R12) is blocked by R01. Pick from the "Teraz" epic: SEC-1, SEC-2, SEC-3.
3. Repo: `github.com/bartek-filipiuk/security-audit-skill` (private, this repo). Landing:
   `github.com/bartek-filipiuk/security-audit-landing` (public), roadmap copy in `src/roadmap.ts`.
4. Before the first change, run the baseline once so you know the numbers you must not lower:
   `node benchmark/setup.mjs --dest <dir>`, `cd <dir>/app && pnpm install`, a fresh Claude Code
   session there, `/security-audit`, then `node benchmark/score.mjs <dir> --label baseline`.
   Reference from 2026-10-03 (Opus 5.5): 16/16 seeded bugs, 0 decoy false positives, 27 verified,
   6 rejected, 32 min, 23.8M tokens.
5. Questions and status: Discord server WrocDevs, channel `#security-audit-skill`. Bartek merges,
   releases and talks to buyers; you do not push to `main`, touch the store or publish.

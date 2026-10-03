# Working on security-audit

For any agent (Codex, Claude Code, a person) who changes this repository. Read it before the first commit.

## What this is

A paid Claude Code skill (147 zł, one-time) that audits the security of a user's own code and produces a
report. Buyers download a ZIP from apps.devince.dev; updates reach them by e-mail as a new link. The
landing is https://security-audit.dev (repo `bartek-filipiuk/security-audit-landing`, public). This repo
is private and is the single source of the product.

Layout: `SKILL.md` (the pipeline), `agents/` (prompts of the sub-agents), `references/` (checklist,
formats, stack patterns), `scripts/` (deterministic pre-pass, state validation, report rendering),
`benchmark/` (Ledgerly, the private test app with 16 seeded bugs and 8 decoys, plus the scorer),
`audit-live/` (optional Claude Code mod), `INSTALACJA.md` and `LICENCJA.md` (shipped to buyers),
`ROADMAP.md` (the plan, ids R01…), `marketing/`.

## Rules that are not negotiable

1. **Defensive by construction.** The skill describes impact and writes regression tests. It never
   writes attack steps, exploit scripts, network tooling or anything that works against another host.
   Keep that in prompts, references, scripts, report wording and commit messages. If a change needs
   attack-style content to work, the change is wrong.
2. **No reassurance without evidence.** A non-issue cites the file:line of the control. A tool that did
   not run is a coverage gap in `not-assessed.md`, never silence.
3. **Benchmark before and after.** Every change to prompts, scripts, models or speed is measured:
   `node benchmark/setup.mjs --dest <dir>`, a fresh Claude Code session in `<dir>/app` with
   `pnpm install` done, `/security-audit`, then `node benchmark/score.mjs <dir> --label "<change>"`.
   The scorer appends to `benchmark/results.jsonl` (gitignored; paste the summary line into the PR).
   Run twice before trusting a difference of one or two bugs. A change that lowers recall or adds a decoy
   false positive does not merge, whatever else it improves.
4. **Scripts have tests.** `node --test scripts/` must pass; the mod: `cd audit-live && claude plugin
   validate . && claude plugin test`. Add a test for every new script behaviour.
5. **Nothing from real projects.** No names, paths, findings or numbers from a customer's or Bartek's
   production project anywhere in the repo, the package or the landing. Ledgerly is the only project
   that may be named. Never commit `.security-audit/` output or `.env` files.
6. **Buyers' files are shipped as-is.** `INSTALACJA.md`, `LICENCJA.md`, `README.md`, `audit-live/README.md`
   are read by customers: Polish for the first two, plain, no internals beyond what the landing says.

## How work flows

- Every roadmap item has an id (`R01`…) in `ROADMAP.md`, the same id in the landing's `src/roadmap.ts`
  and a task in devince-crm. Start from the task; when the item moves lane (Now → Done), update all three.
- Branch per item: `r01-incremental-audit`. Small commits in English, no AI attribution lines.
  Open a PR with: what changed, the benchmark line before and after, and the test output.
- Bartek merges and releases. Do not push to `main`, do not touch the store, do not publish anything.
- A stack profile (R02, R05, R06, R09, R10, R16) consists of: entry-point detection in
  `scripts/surface.mjs`, hotspot signals, patterns in `references/stack-patterns.md`, checklist items,
  deterministic scanners wired into `scripts/prepass.mjs` with honest NOT RUN handling, and its own
  benchmark app under `benchmark/<name>/` with an answer key in the Ledgerly format. It ships only when
  the scorer runs on that app.
- Deterministic tools: run natively if installed, else through their official docker image, else report
  NOT RUN with how to enable. Their output goes to `.security-audit/tools/` and appears in `prepass.md`
  as candidates. The model verifies; the tool never writes a finding.
- Token cost matters. Report the token and minute numbers from the benchmark run with every PR that
  touches prompts or the pipeline.

## Releasing (Bartek, or on his explicit request)

1. Bump the version in `INSTALACJA.md` and `LICENCJA.md`, add the entry under Done in `ROADMAP.md` and
   in the landing's `src/roadmap.ts`.
2. Build the ZIP with `scripts/package.sh <out-dir>` (it excludes the repo-only files, puts
   `devince-install.json` at the archive root for `npx @devince/apps install`, and refuses private strings).
   Unpack the result and run the tests from inside it.
3. Upload to the store (`POST /app-assets`), point the product's `downloadFiles` at the new asset,
   then `POST /products/<id>/notify-buyers` so buyers get a fresh link. Credentials are not in this repo.

## Where to ask

Discord server WrocDevs, channel `#security-audit-skill`. Bartek decides scope and releases.

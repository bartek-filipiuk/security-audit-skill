# Benchmark: Ledgerly

A small multi-tenant SaaS in the stack this skill is used on (Next.js 16 App Router, Better-Auth with
organizations, Drizzle on Postgres, tRPC, a Hono public API, pg-boss, Stripe, Resend, R2 presigned
uploads, AI SDK tools). It contains 23 seeded vulnerabilities and 13 decoys (secure code that looks
suspicious); until R08 (2026-10-06) it had 16 and 8, R08 made it 20 and 11, and R21 23 and 13, so compare
recall only between runs on the same key. It was written for this skill and was private until the project went open source on
2026-10-03, so treat later results with care: it may reach model training data. The skill was also
developed against it, so a high score shows these bug classes are covered, not how much the skill finds in
arbitrary code. A second, never-published app is on the roadmap (R18).

Use it before and after any change to the skill, a model, or a speed optimisation. Without a number
from here you cannot tell whether "faster" cost recall.

## Run

    node benchmark/setup.mjs                  # prints the run directory
    cd <run>/app && claude                    # fresh session, then: /security-audit
    node benchmark/score.mjs <run> --label "what changed"
    node benchmark/usage.mjs <session id>       # tokens and API-price cost, subagents included

Headless instead of an interactive session:

    cd <run>/app && CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0 claude -p "/security-audit" \
      --dangerously-skip-permissions --output-format json --session-id <uuid>

Without `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0` print mode stops background subagents (the Phase 3
verifiers) after 600 s and exits with no report.

Incremental run (`--since`): after a full run, copy the run directory, make and commit a small change in
`<copy>/app`, set `started_at` in `<copy>/meta.json` to now, then run `/security-audit --since <commit>` there
and score the copy. `score.mjs` prints how many found bugs were carried over.

To score the Claude Security plugin on the same app, run `/claude-security` in `<run>/app` and add
`--tool claude-security` to the score command. See COMPARISON.md for the first head-to-head.

`setup.mjs` copies `app/` to a temp directory and builds a two-commit git history in which a
Stripe-format live key is committed and then deleted (generated at runtime, so this repo never
contains it). The audit only ever sees `<run>/app`.

`score.mjs` prints recall, findings the verifier wrongly rejected (`dropped_by_verifier`), decoy false
positives, known extras (real advisories in the pinned dependencies), verified findings that matched
nothing with their location (read those by hand), the match type (`exact` or `none`) and proof label of
each seeded bug, and the run time. It appends one line to `results.jsonl`.

## Rules

- Never copy `answer-key.json` or this README into the audited directory, and never mention the
  seeded bugs in the prompt. The app source has no hint comments; keep it that way.
- Compare runs on the same model and effort. Expect run-to-run variance: run twice before trusting
  a difference of one or two bugs.
- Matching is exact, by file and line; there are no keywords and no fallback. A finding's primary
  location is the first `**File**:` line of its Evidence (else the first `path:line` it cites); other files
  it cites are context and never match. It matches a key entry when the path ends with the entry's file
  and the line is inside one of the entry's ranges or at most `window` (2) lines outside it. When several
  entries are in reach, the nearest wins, so neighbouring ranges in one file (B06 and decoy D04) stay apart.
  `advisory: true` entries (vulnerable dependency versions) take only findings in category `dependency`,
  and those findings match nothing else, except `any_category: true` entries (supply-chain settings in a
  manifest, which an auditor may file as `config` or `dependency`). A finding without a line matches nothing.
  Cited files may be code, manifests, CI workflows (`.github/workflows/*.yml`), Dockerfiles, compose and IaC files.
- A range is the vulnerable statement or the lines a fix changes, not the whole file. Decoy ranges
  cover the code that looks suspicious. When a real finding is scored as unmatched, check the range
  against the code and fix the key, not the finding.
- When you add a seeded bug: add it to `app/` without comments, add an entry to `answer-key.json`
  with `locations` (file and inclusive line range), `detect` and `why`, and rerun
  `node --test scripts/*.test.mjs`; `scripts/score.test.mjs` checks that every range points at real,
  non-blank lines and that ranges do not overlap. Editing a seeded file moves lines: update the ranges.

## Seeded classes

BOLA in a server action and in a tRPC mutation, tenant id taken from the query string, admin API
outside the proxy matcher, full DB row serialized to a public client component, cross-tenant
`unstable_cache` key, secret API key behind `NEXT_PUBLIC_`, unsigned Stripe webhook, SSRF that
returns the response body, AI tool that takes `orgId` from the model, presigned upload key from the
client, `role` mass assignment through Better-Auth `additionalFields`, digest job emailing every
user, vulnerable Next.js version reachable through `images.remotePatterns`, live key in git history,
CORS reflecting any origin with `SameSite=None` cookies; since R08 also a cookie-authenticated route handler
without an origin check (CSRF), a `pull_request_target` workflow that builds the pull request head with
secrets, runtime secrets baked into the image through Dockerfile `ARG`/`ENV`, and a `postinstall` script that
pipes an unpinned download into a shell. Decoys added with them: a server action (origin-checked by Next.js),
a CI workflow that passes PR text through `env:`, and a compose file with a localhost-only database port.
Since R21: an invoice summary that renders model output (built from invoice notes) as raw HTML, an agent tool
that voids any invoice by a model-chosen id with no tenant scope, role check or approval, and an agent route
that takes the model, output tokens and step count from the request body. Decoys added with them: a reminder
email whose model-written text is HTML-escaped and whose recipient comes from the org-scoped database row, and
an org-scoped tool that requires approval (`needsApproval`). The seeded LLM code calls no model unless the app
runs with a key. Details: `answer-key.json`.

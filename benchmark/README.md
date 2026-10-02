# Private benchmark: Ledgerly

A small multi-tenant SaaS in the stack this skill is used on (Next.js 16 App Router, Better-Auth with
organizations, Drizzle on Postgres, tRPC, a Hono public API, pg-boss, Stripe, Resend, R2 presigned
uploads, AI SDK tools). It contains 16 seeded vulnerabilities and 8 decoys (secure code that looks
suspicious). It is private and new, so unlike OWASP Juice Shop it cannot be in a model's training data.

Use it before and after any change to the skill, a model, or a speed optimisation. Without a number
from here you cannot tell whether "faster" cost recall.

## Run

    node benchmark/setup.mjs                  # prints the run directory
    cd <run>/app && claude                    # fresh session, then: /security-audit
    node benchmark/score.mjs <run> --label "what changed"

`setup.mjs` copies `app/` to a temp directory and builds a two-commit git history in which a
Stripe-format live key is committed and then deleted (generated at runtime, so this repo never
contains it). The audit only ever sees `<run>/app`.

`score.mjs` prints recall, findings the verifier wrongly rejected (`dropped_by_verifier`), decoy false
positives, known extras (real advisories in the pinned dependencies), verified findings that matched
nothing (read those by hand), the proof label of each found bug, and the run time. It appends one
line to `results.jsonl`.

## Rules

- Never copy `answer-key.json` or this README into the audited directory, and never mention the
  seeded bugs in the prompt. The app source has no hint comments; keep it that way.
- Compare runs on the same model and effort. Expect run-to-run variance: run twice before trusting
  a difference of one or two bugs.
- Matching is by cited file plus keyword. A keyword must not appear in a file name it is paired with
  (`next` + `next.config.ts` matches everything). When a real finding is scored as unmatched, fix the
  key, not the finding.
- When you add a seeded bug: add it to `app/` without comments, add an entry to `answer-key.json`
  with `files`, `keywords`, `detect` and `why`, and rerun `node --test scripts/`.

## Seeded classes

BOLA in a server action and in a tRPC mutation, tenant id taken from the query string, admin API
outside the proxy matcher, full DB row serialized to a public client component, cross-tenant
`unstable_cache` key, secret API key behind `NEXT_PUBLIC_`, unsigned Stripe webhook, SSRF that
returns the response body, AI tool that takes `orgId` from the model, presigned upload key from the
client, `role` mass assignment through Better-Auth `additionalFields`, digest job emailing every
user, vulnerable Next.js version reachable through `images.remotePatterns`, live key in git history,
CORS reflecting any origin with `SameSite=None` cookies. Details: `answer-key.json`.

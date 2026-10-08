# Benchmark: Ledgerly

A small multi-tenant SaaS in the stack this skill is used on (Next.js 16 App Router, Better-Auth with
organizations, Drizzle on Postgres, tRPC, a Hono public API, pg-boss, Stripe, Resend, R2 presigned
uploads, AI SDK tools). It contains 16 seeded vulnerabilities and 8 decoys (secure code that looks
suspicious). It was written for this skill and was private until the project went open source on
2026-10-03, so treat later results with care: it may reach model training data. The skill was also
developed against it, so a high score shows these bug classes are covered, not how much the skill finds in
arbitrary code. A second, never-published app is on the roadmap (R18).

Use it before and after any change to the skill, a model, or a speed optimisation. Without a number
from here you cannot tell whether "faster" cost recall.

## Run

    node benchmark/setup.mjs                  # prints the run directory (--app supabase-notes, php-tickets or py-clinic)
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

## Second app: supabase-notes

`benchmark/supabase-notes/` is the benchmark of the Supabase and Firebase profile (roadmap R02): a Next.js
notes app on Supabase (SQL migrations with RLS policies, a SECURITY DEFINER RPC, storage buckets and
policies, two Edge Functions and `config.toml`) with Firestore whiteboards (`firestore.rules`,
`storage.rules`, callable Cloud Functions). 10 seeded bugs and 12 decoys; the key is
`benchmark/supabase-notes/answer-key.json`, in the same format and with the same matching rules.

    node benchmark/setup.mjs --app supabase-notes   # one commit, meta.json records bench_app
    cd <run>/app && claude                          # fresh session, then: /security-audit
    node benchmark/score.mjs <run> --label "what changed"   # picks the key from meta.json (or --app)

It has no lockfile, so the dependency scan has nothing to read there; a finding about the missing lockfile
is valid and shows up as unmatched. Seeded classes: a table without RLS, `using (true)` on private notes,
an update policy that checks login instead of ownership, a SECURITY DEFINER RPC without an ownership check or
`search_path` and executable with the anon key, bucket-wide storage policies, the service-role key behind
`NEXT_PUBLIC_` imported by a client component, an Edge Function with `verify_jwt = false` that trusts a user
id from the body, Firestore rules that treat any signed-in user as owner, Storage rules `if true`, and a
callable Cloud Function without an auth check (App Check only). Decoys: a public price table, scoped
SECURITY DEFINER functions, column-limited profile updates, browser updates guarded by RLS, a public avatars
bucket with owner-scoped writes, a server-only service-role client, the anon key and Firebase web config, a
webhook Edge Function that verifies an HMAC, and owner-scoped rules and callables.

## Third app: php-tickets

`benchmark/php-tickets/` is the benchmark of the PHP profile (roadmap R05): a Laravel helpdesk (routes,
controllers, models, a CSRF middleware, Blade views) with a Symfony billing service in `billing/` (attribute
routes, Doctrine repository, voter, `security.yaml`) and a Drupal custom module in `portal/` (routing.yml,
controller). Plain PHP files laid out like the real frameworks: no `vendor/`, nothing to install, nothing to
run. 13 seeded bugs and 14 decoys; the key is `benchmark/php-tickets/answer-key.json`.

    node benchmark/setup.mjs --app php-tickets      # one commit, meta.json records bench_app
    cd <run>/app && claude                          # fresh session, then: /security-audit
    node benchmark/score.mjs <run> --label "what changed"

Laravel keeps its code in `app/`, the same name as the run directory: the scorer compares a cited path with
and without the leading `app/`, so `app/Http/...` and `app/app/Http/...` both match. There is no
`composer.lock`, so the dependency scan has nothing to read; Psalm taint analysis is NOT RUN by design.
Seeded classes: Laravel `findOrFail($id)` without a user scope or policy, `whereRaw` with an interpolated
search term, `update($request->all())` on a model with `$guarded = []`, an API route outside the
`auth:sanctum` group, `{!! !!}` on comment bodies, a CSRF exception on `account/*`, uploads stored on the
public disk under the client file name; Symfony DQL built by concatenation (and not scoped to the customer)
and `find($id)` behind a login-only `IsGranted`; Drupal `_access: 'TRUE'` on a route serving tickets, a
concatenated `database()->query()`, a state-changing GET route without `_csrf_token`, and `Markup::create()`
on user text. Decoys: a policy-checked update, a bound `whereRaw`, `create($request->validated())`, an
HMAC-verified webhook outside auth and CSRF, an admin group with `can:admin`, `{!! nl2br(e()) !!}`, a
validated avatar upload, a parameterised QueryBuilder, a voter-checked PDF download, a public status route,
a placeholder query, a reopen route with `_csrf_token`, `#markup` through `t()` placeholders and
`APP_DEBUG=true` only in `.env.example`.

## Fourth app: py-clinic

`benchmark/py-clinic/` is the benchmark of the Python profile (roadmap R06): a Django patient portal
(`clinic/` settings and urls, `appointments/` with views, templates and a DRF API, `records/`, a payment
webhook in `payments/`) with a FastAPI lab service in `labs/` (routers, SQLAlchemy models, pydantic schemas,
cookie auth) and a Flask back office in `backoffice/` (blueprint, Flask-Login, Jinja templates). Plain
Python files laid out like the real frameworks: no virtualenv, nothing to install, nothing to run; the
`requirements.txt` files are pinned. 18 seeded bugs and 18 decoys; the key is
`benchmark/py-clinic/answer-key.json`.

    node benchmark/setup.mjs --app py-clinic        # one commit, meta.json records bench_app
    cd <run>/app && claude                          # fresh session, then: /security-audit
    node benchmark/score.mjs <run> --label "what changed"

The scorer parses `.py`, `.html`, `.txt`, `.cfg` and `.ini` locations. bandit is NOT RUN by the pre-pass
until R07; osv-scanner reads the three `requirements.txt` files, and an advisory it reports for a pinned
version is not in the key (it shows up as an unmatched finding, not as a decoy false positive).
Seeded classes: Django `get_object_or_404(pk=)` without a patient filter, `.raw()` with an f-string, a DRF
viewset whose queryset is every patient's prescriptions, a patient CSV export without `login_required`,
`|safe` on message bodies, `csrf_exempt` on a session view that changes the account e-mail, a literal
`SECRET_KEY` fallback, an upload path from a form field, `yaml.load` with `yaml.Loader`; FastAPI a PDF route
without the auth dependency that loads any result by id, `text()` with an f-string, a `BackgroundTasks`
callback to a caller-chosen URL whose reply is stored and returned, a `response_model` with password hashes
and TOTP secrets, CORS `*` with credentials; Flask `render_template_string` on the letter body, `send_file`
with a joined query parameter, a role change route without `login_required`, a literal `secret_key`.
Decoys: owner-filtered lists and gets, a parameterised `.raw()`, a scoped `get_queryset`, `AllowAny` on the
read-only doctors directory, `format_html`, a signed webhook with `csrf_exempt`, DEBUG and hosts from the
environment (`DJANGO_DEBUG=1`/`FLASK_DEBUG=1` only in `.env.example`), an owner-checked download, a scoped
result route, a bound `text()`, router-level `Depends(require_staff)` with a public schema on `/staff/me`, a
health check, `render_template` with a variable, `send_from_directory` with `secure_filename`,
`yaml.safe_load` and the public sign-in view.

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
  and those findings match nothing else. A finding without a line matches nothing.
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
CORS reflecting any origin with `SameSite=None` cookies. Details: `answer-key.json`.

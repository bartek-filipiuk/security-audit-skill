# Security Audit Checklist

Full checklist for Phase 2: Targeted Audit. Verify each applicable category based on Phase 1 recon.
Skip categories that don't apply to the detected stack.

## 2.1 Authentication & Authorization

- [ ] Passwords hashed with strong algorithm (bcrypt/scrypt/argon2), never logged or returned in responses
- [ ] Token/session expiry enforced, tokens validated on every protected endpoint
- [ ] Authorization checks on every mutating endpoint (not just auth, but ownership/role)
- [ ] No endpoint accessible without intended auth (search for unprotected routes)
- [ ] Secrets (JWT key, API keys, DB passwords): loaded from env, no hardcoded defaults usable in production, fail-fast if missing
- [ ] Session ID generation: verify session IDs use cryptographic RNG (not sequential, not timestamp-based, not `mt_rand()`). Check for `HttpOnly` and `Secure` flags on session cookies
- [ ] Account lockout: failed login attempts tracked and rate-limited. Verify lockout mechanism exists (time-based delay, account lock after N failures, or progressive backoff)
- [ ] Cookie-based auth checks: authorization decisions must use server-side session data, NOT client-controllable cookies. Search for `$_COOKIE` / `req.cookies` in auth logic
- [ ] BOLA on read: route handlers accepting ID parameters (`:id`, `{id}`, `<id>`) must verify the authenticated user owns the fetched object before returning it. Search for `findOne`/`findById`/`get` with route param but WITHOUT ownership filter (e.g., missing `UserId: authenticatedUser.id` in query)
- [ ] BOLA on write: PUT/PATCH/DELETE on `/:id` resources must include ownership filter in the UPDATE/DELETE query itself, not just in a preceding SELECT. Search for `update`/`delete` with `req.params.id` or `req.body.id` without owner scope
- [ ] BFLA — admin routes: endpoints with "admin" in path must have admin-specific middleware/decorator, not just generic auth. Search for routes containing `/admin` without role verification
- [ ] BFLA — HTTP method consistency: if GET on a resource requires auth, verify POST/PUT/DELETE on the same resource also requires auth (at same or higher level). Search for method handlers on same path with different protection levels
- [ ] BFLA — state-changing without auth: POST/PUT/DELETE endpoints that modify data (checkout, upgrade, transfer, delete) must have explicit auth middleware. Search for state-changing routes without any auth decorator/middleware
- [ ] Tenant scope on every query, not only on `/:id` routes: list, search, export, report, dashboard and job queries filter by the owner/tenant column. Resolve every pre-pass Data Scope Scan candidate (UNSCOPED / PARENT-ONLY) to a finding or to a non-issue citing where scoping happens
- [ ] Owner/tenant id comes from the session, never from body, query, params, a tool argument or a job payload without a membership check (`searchParams.get("org")`, `input.orgId`, `job.data.userId`)
- [ ] Proximity-only controls: auth that lives only in `proxy.ts`/`middleware.ts`, a layout or a page does not protect server actions, route handlers or tRPC procedures that reuse the same data. Each entry point enforces its own check; paths outside the proxy `matcher` get no check at all

### CSRF (category `auth`)

Applies to every endpoint that authenticates by cookie. Bearer-token and API-key endpoints are not CSRF targets.

- [ ] Every cookie-authenticated state change (POST/PUT/PATCH/DELETE route handler, API route, form endpoint) has its own forgery control: an Origin or `Sec-Fetch-Site` check against an allowlist, a CSRF token, or a custom header/JSON content type it actually enforces. Non-issue evidence is the file:line of that check, or the framework protection plus its config line: Next.js server actions compare Origin with Host unless `serverActions.allowedOrigins` widens it, Better-Auth endpoints check `trustedOrigins`, Django `CsrfViewMiddleware`, Rails `protect_from_forgery`, Laravel `VerifyCsrfToken`. Custom route handlers next to them inherit none of it
- [ ] Cookie attributes: session cookies are `SameSite=Lax` or `Strict`. `SameSite=None` (embedded widgets, `crossSubDomainCookies`, `defaultCookieAttributes`) means every cookie-authenticated state change needs its own origin check; cite the cookie config line together with each unprotected handler
- [ ] No state change on GET (accept invitation, delete, toggle, connect integration, change plan): `SameSite=Lax` still sends cookies on top-level GET navigations. Search for `export async function GET` / `app.get` handlers that write
- [ ] Body parsing: a handler that reads `request.formData()`, `request.text()` + `JSON.parse`, or accepts `application/x-www-form-urlencoded`, `multipart/form-data` or `text/plain` can be reached by a cross-site form without a CORS preflight. A handler that requires `application/json` and rejects other types is protected only if CORS does not allow credentialed cross-origin requests (see 2.5)
- [ ] OAuth/SSO callbacks validate `state` (or PKCE) bound to the user's session before linking an account or storing a provider token. Evidence: the line that compares `state` with the stored value
- [ ] CSRF exemptions (`csrf_exempt`, `$except`, `skip_forgery_protection`, a matcher that skips paths) cover only machine endpoints that verify a signature (webhooks)

### LLM tools and agents (category `auth`)

Applies when the project calls a model with tools or runs an agent (AI SDK `tool()`, OpenAI or Anthropic tool use, LangChain tools and agents, MCP servers). Every tool argument, and everything the model reads (user messages, documents, emails, web pages, database text, tool results), is attacker-controlled input: a system prompt does not prevent prompt injection.

- [ ] Each tool's `execute` enforces the authorization the equivalent route handler would need: owner/tenant scope from the session context captured when the tools are built (`ctx.orgId`), never a model-supplied id on its own, and the same role check. Evidence: the scoped `where` line inside the tool. "The system prompt says only this organization" or a tool description is not a control
- [ ] Destructive or outbound tools (delete, void, refund, payment, send email or message, change a role, write files, run code, call a URL) need a confirmation the model cannot give itself (`needsApproval` in AI SDK, an approval step in the agent loop, a separate confirmed server action), or are limited to reversible effects in the caller's own scope. Evidence: the approval flag or the confirmation endpoint
- [ ] Tools are built per request from the caller's permissions: a member's chat does not get admin-only tools, and an MCP server or agent exposes nothing the user could not call directly. Targets the model chooses (email recipient, webhook URL, file path, record id) are limited to the tenant's own records or an allowlist
- [ ] Indirect prompt injection: when the model reads untrusted content (customer messages, uploaded documents, fetched pages, text other users wrote) in the same loop as tools with side effects or with access to private data, cite the tool line as the finding and name the untrusted source in Impact. Agent loops have a fixed step limit (`stopWhen`, `max_iterations`, `max_turns`)

## 2.2 Input Validation & Injection

- [ ] SQL: All queries parameterized (no string concatenation/interpolation). Search for raw SQL, `execute()`, f-strings/template literals near queries
- [ ] XSS: User content escaped on render. Search for `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `|safe`, `raw()`, `bypassSecurityTrust`, unescaped template vars
- [ ] XSS via file content: files read from disk (subtitles, templates, configs) injected into HTML responses without encoding. Search for `fs.readFile` → `res.send`/template interpolation paths
- [ ] SVG injection: if SVG uploads accepted, verify SVG content sanitized (can contain `<script>`, `onload=`, external entities). SVGs served with `Content-Type: image/svg+xml` execute JS in browser
- [ ] CSP bypass: if legacy pages exist with custom sanitizers (regex-based), note that a regex sanitizer is incomplete by construction and recommend a maintained sanitizer. Also check if CSP header is set per-page or has unsafe-inline
- [ ] Command injection: No user input in shell commands. Search for `exec`, `spawn`, `system`, `subprocess`, `os.popen`
- [ ] Path traversal: File-serving endpoints validate filenames (no `../`). Search for path join with user input
- [ ] Deserialization: No unsafe deserialization of user input (pickle, yaml.load, JSON.parse on unvalidated blobs)
- [ ] Open redirect: redirect/forward targets validated against allowlist. Search for `redirect`, `Location:`, `res.redirect`, `header("location`)` with user-controlled URL. `url.includes()` substring check is bypassable
- [ ] NoSQL injection: MongoDB/NoSQL queries don't accept operator objects from user input. Search for `$where`, `$gt`, `$ne`, `$regex` in query filters built from `req.body`/`req.query`
- [ ] SSTI (Server-Side Template Injection): user input not passed to template engine `render()`/`compile()` as template string (vs. as data). Search for `render(userInput)`, `eval()`, `new Function()`, template literal with user data
- [ ] Prototype pollution: no uncontrolled recursive merge/clone of user input into objects. Search for `Object.assign`, `_.merge`, `_.defaultsDeep`, `deepmerge` with `req.body`. Check `__proto__`, `constructor.prototype` paths
- [ ] LDAP injection: LDAP queries use parameterized filters, not string concatenation. Search for `ldap.search`, `ldap_search`, filter strings with user input
- [ ] Host header injection: `Host` / `X-Forwarded-Host` headers not used to build URLs (password reset links, redirects, canonical URLs). Search for `req.headers.host` / `$_SERVER['HTTP_HOST']` in URL construction
- [ ] Second-order injection: data stored safely but later retrieved and used unsafely in a different context (e.g., username stored escaped for SQL but later used unescaped in shell command or template)
- [ ] GraphQL: if GraphQL endpoint exists, verify introspection disabled in production (`introspection: false`), query depth/complexity limited, and field-level authorization enforced

### LLM output and model context (category `injection`; secrets in context `exposure`)

Model output is untrusted input: anything that reaches the prompt (user text, stored records, documents, tool results) can shape it. Asking the model for "safe" output is not a control.

- [ ] HTML: model output is not rendered with `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `|safe`, or a markdown renderer that passes raw HTML (`marked` without a sanitizer, `markdown-it({ html: true })`, `react-markdown` with `rehype-raw`) unless a sanitizer (DOMPurify, `rehype-sanitize`) runs on it; the same holds for email HTML built from model output. Evidence: the escape or sanitize call applied to the output
- [ ] SQL and queries: model output (text-to-SQL, generated filters or `where` objects) never runs as raw SQL or as an operator object; generated queries run on a read-only connection limited to the caller's tenant (row-level security or views) with an allowlist of tables. Evidence: the parameterized query or the restricted connection
- [ ] Shell, code and files: model output never reaches `exec`/`spawn` with a shell, `eval`/`new Function`, Python `exec`/`subprocess`, a code interpreter on the host, or a file path, without a sandbox and an allowlist
- [ ] URL and fetch (SSRF): URLs the model chooses (browse, fetch, webhook, image tools) pass the same allowlist and private-address checks as user-supplied URLs, redirects included, and fetched pages are untrusted content. Rendered markdown images and links to arbitrary hosts can carry private data out in the URL: restrict image hosts or strip them
- [ ] Structured output: JSON and tool arguments from the model are validated with a schema (`zod`, `inputSchema`, a JSON-schema `response_format`) before use, with enums for actions and ids checked against the caller's scope
- [ ] Context contents: no API keys, connection strings, internal URLs or other tenants' records in system prompts, tool results or retrieved documents (a RAG index is filtered by tenant at query time). Assume the user can read the system prompt. Category `exposure`

## 2.3 Rate Limiting & Abuse Prevention

- [ ] Auth endpoints (login, register, password reset) rate-limited
- [ ] Resource-creation endpoints rate-limited (prevent spam)
- [ ] File upload size limits enforced
- [ ] If rate limiting claimed: verify it's actually active (not disabled in config, not bypassed in tests)
- [ ] LLM endpoints (chat, completion, agent, embedding, image generation): per-user or per-tenant rate and spend limits exist, and the model id, `max_tokens`/`maxOutputTokens`, agent step count and context size are fixed or capped on the server, never taken from the request. Anonymous and trial access to paid models is limited. Provider keys stay server-side (no `NEXT_PUBLIC_`/`VITE_` key, no `dangerouslyAllowBrowser: true`, no `anthropic-dangerous-direct-browser-access`). Evidence: the limiter or quota line and the constant model id

## 2.4 Data Exposure

- [ ] Error responses don't leak stack traces, internal paths, or DB structure in production mode
- [ ] API responses don't over-expose fields (no password hashes, internal IDs, admin flags returned to non-admins)
- [ ] Logs don't contain secrets, tokens, or passwords
- [ ] .env / credentials files in .gitignore
- [ ] Pre-pass secret scan (gitleaks, whole git history): every real credential that was ever committed is a finding until rotated, even if the file is gone. Fixtures and placeholders are non-issues

## 2.5 Security Headers & Transport

- [ ] CORS: Origin allowlist (not wildcard `*` in production), appropriate methods/headers
- [ ] Security headers present: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy
- [ ] HTTPS enforced (HSTS, redirect HTTP->HTTPS) if applicable
- [ ] CSP trusted domains: if CSP uses domain allowlist, verify listed domains don't host user-controlled content (CDNs like jsdelivr/unpkg, pastebins, JSONP endpoints). Scripts hosted there run under the policy

## 2.6 File Upload

Skip if no upload endpoints found in recon.

- [ ] MIME type validated (not just extension)
- [ ] File size limit enforced before reading into memory
- [ ] Image files verified (magic bytes or library validation)
- [ ] Uploaded files served from a separate domain/path, not executed
- [ ] ALL endpoints that accept files share the same validation (no bypass via alternate endpoint)
- [ ] Null byte injection: if file paths validated by extension, verify null bytes stripped BEFORE validation (not after). `file.pdf%00.exe` may pass `.pdf` check but execute as `.exe`
- [ ] Upload size config: verify upload middleware has explicit `limits.fileSize` configured (not just frontend validation). Search for multer/busboy/formidable config
- [ ] Extension vs content validation: verify file type checked by content/magic bytes, not just filename extension. Extension-only check allows renaming disguised files

## 2.7 Dependency, Supply Chain & Build Pipeline Security

- [ ] All dependencies pinned to specific versions (lockfile present and committed)
- [ ] Known advisories come from the pre-pass dependency scan (osv-scanner), never from memory. Prod tree + plausibly reachable code path → finding (cite the lockfile line and where the feature is used); dev-only → recommendation unless it runs in CI/build on untrusted input or a dev server is exposed. Scan NOT RUN → not-assessed, not "no CVEs"
- [ ] No unnecessary dependencies (more exposed code from unused packages)
- [ ] Transitive dependency risks: critical path depending on single-maintainer package?
- [ ] Dependency update mechanism exists (Dependabot, Renovate, or documented process)
- [ ] No dependencies pulled from non-standard registries without verification

Findings from the three subsections below use category `config`; `dependency` stays for known-vulnerable versions. A subsection whose files do not exist in the repo is skipped (say so in recon, not as a non-issue). CI that runs in another repository or system the audit cannot see goes to `not-assessed.md`.

### Install scripts and lockfile integrity

- [ ] The project's own `preinstall`/`install`/`postinstall`/`prepare` scripts in `package.json` (and `composer.json` scripts, `setup.py` hooks) do not download and execute remote code (`curl … | sh`, `wget -O- … | bash`, fetch-and-eval) without a pinned version and a checksum or signature check. They run on every developer machine, every CI job and every image build. Evidence of the control: the checksum verification line, or the script that installs a pinned, verified artifact
- [ ] Dependency lifecycle scripts: npm and Yarn run them unless `ignore-scripts=true`; pnpm 10+ blocks them unless allowed. Check `onlyBuiltDependencies`/`neverBuiltDependencies`/`dangerouslyAllowAllBuilds` in `package.json`, `.npmrc` and `pnpm-workspace.yaml`. A blanket allow, in CI jobs that hold secrets, widens the impact of any compromised transitive package
- [ ] Lockfile enforced at install: CI and Dockerfiles use `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`, `bun install --frozen-lockfile`, `composer install` (not `update`), `pip install --require-hashes` or `uv sync --locked`, and the Dockerfile copies the lockfile before installing. Evidence: the install line
- [ ] Lockfile integrity: registry entries carry an integrity hash (`integrity:` / `resolution: {integrity: …}`); resolved and tarball URLs use https and the expected registry host. An unexpected host or a missing hash in a changed lockfile is a finding to raise even when `package.json` looks unchanged
- [ ] Unpinned sources: no dependency resolved from a git branch or tag (`github:org/repo`, `git+https://…#main`), a bare http(s) tarball URL, or a `latest`/`*` range; a git dependency is pinned to a commit SHA
- [ ] Registry configuration: internal scoped packages have a scoped registry in `.npmrc` (otherwise the public registry may serve a same-named package), registry auth tokens come from an environment variable, not a literal in the file

### CI/CD workflows

GitHub Actions (`.github/workflows/*.yml`); apply the same ideas to GitLab CI, CircleCI, Bitbucket and Jenkinsfiles.

- [ ] `pull_request_target` and `workflow_run` jobs never check out or execute the pull request's code (`ref: ${{ github.event.pull_request.head.sha }}` or `head.ref`, `refs/pull/<n>/merge`, `gh pr checkout`, running artifacts of the triggering run) while secrets or a write token are available. Installing dependencies and building count as executing it. Evidence of the control: the `on:` line (`pull_request`, which gives fork runs no secrets) or a checkout of the base ref only
- [ ] Expression injection: attacker-controlled context (`github.event.issue.title`/`body`, `pull_request.title`/`body`/`head.ref`, `github.head_ref`, `comment.body`, `review.body`, commit messages, `discussion.*`, `pages.*.page_name`) never appears as `${{ … }}` inside `run:` or an `actions/github-script` `script:`. Control: passed through `env:` and used as a quoted shell variable; cite the `env:` line
- [ ] Secrets stay out of logs and artifacts: no `echo`/`printf`/`set -x`/`env`/`printenv` with secrets, no secret written to `$GITHUB_OUTPUT`, `$GITHUB_STEP_SUMMARY`, artifacts or caches, no transformed secret (base64, JSON, URL with credentials) printed, since masking only hides the exact string. Control: the secret reaches the tool only as an env var or input
- [ ] Actions pinned: third-party `uses:` refer to a full 40-character commit SHA (tags and branches can be moved by whoever controls the action); `docker://` images by digest. First-party `actions/*` by SHA or by tag with Dependabot or Renovate updating them. Evidence: the `uses:` line
- [ ] Token scope: workflow or job `permissions:` set to the minimum (`contents: read` by default), no `write-all`; `actions/checkout` uses `persist-credentials: false` in jobs that build untrusted code; deploy secrets live in an environment with required reviewers
- [ ] Self-hosted runners are not used by workflows that fork pull requests can trigger

### Containers and infrastructure as code

Dockerfiles, `docker-compose*.yml`, Kubernetes manifests and Helm values, Terraform, CloudFormation, Pulumi.

- [ ] No secrets in images: no secret in `ENV` or `ARG` (ARG values are kept in the image history, ENV in the image config), no `COPY .env` or key files, and `.dockerignore` excludes `.env*`, `.git` and keys before a broad `COPY . .`. Control: `RUN --mount=type=secret`, or secrets injected at run time by the platform
- [ ] Non-root: the final stage sets `USER` to a non-root user (or the orchestrator sets `runAsNonRoot`); no `privileged: true`, `cap_add: [SYS_ADMIN]`, `hostNetwork`, `hostPID` or Docker socket (`/var/run/docker.sock`) mount in application containers
- [ ] Reproducible inputs: base images pinned to a version tag (by digest for production), never `latest` or no tag; `ADD <url>` and `curl` downloads in `RUN` verified with a checksum; package managers in the build use the lockfile (see above)
- [ ] Published ports: databases, caches, queues and admin UIs are published only on `127.0.0.1` or kept on an internal network. `"5432:5432"` listens on every interface and Docker's iptables rules bypass host firewalls such as ufw. Evidence: the `ports:` line
- [ ] Cloud resources: no public storage buckets or ACLs, no security group or firewall rule open to `0.0.0.0/0` on database, SSH or admin ports, no plaintext secrets in variables, `tfvars` or committed state, storage and databases encrypted at rest. A finding only when the file is the deployed configuration; example or local-only files are recommendations

## 2.8 Cryptography

Skip if no crypto code found in recon.

- [ ] No broken algorithms: MD5, SHA1 for security purposes, DES, RC4, ECB mode
- [ ] Proper key sizes: RSA >= 2048, AES >= 128, ECDSA >= 256
- [ ] Random number generation uses cryptographic RNG (not Math.random, not random.random for security)
- [ ] No hardcoded keys, IVs, or salts
- [ ] Insecure randomness: security-sensitive values (session IDs, tokens, nonces, password reset codes) must use cryptographic RNG — not `Math.random()`, `rand()`, `mt_rand()`, `random.random()`, sequential counters, or timestamps
- [ ] TLS version >= 1.2, no SSLv3/TLS 1.0/1.1 support
- [ ] If custom crypto exists: flag it. Custom crypto is almost always wrong
- [ ] Key rotation mechanism exists or is documented
- [ ] JWT algorithm enforcement: verify server REJECTS `alg: "none"` tokens. Check jwt.verify() options — must specify `algorithms: ['RS256']` (or explicit list), not accept any
- [ ] JWT algorithm confusion: if RSA signing used, verify server rejects HMAC tokens signed with the public key. Public key exposed in source + HS256 accepted = forged token
- [ ] JWT public key exposure: if RSA keys used, check whether public key is accessible (source code, /.well-known/, API endpoint). Accessible key + missing algorithm restriction = forgery
- [ ] Sensitive secrets (TOTP, MFA, recovery codes) stored encrypted at rest, not plaintext in DB columns

## 2.9 Concurrency & Race Conditions

- [ ] Check-then-act patterns: gap between authorization check and action? (TOCTOU)
- [ ] Shared mutable state: counters, balances, quotas updated atomically?
- [ ] Database transactions: multi-step operations use transactions where needed?
- [ ] File system races: temp file creation, lock files, concurrent writes
- [ ] Double-submit: can a request be replayed concurrently for duplicate effect? (double-spend, double-claim)
- [ ] WebSocket security: if WebSocket/Socket.IO used, verify origin validation on upgrade, auth token checked on connection (not just HTTP handshake), and messages validated/sanitized same as HTTP input

## 2.10 Documentation vs Reality

For every security claim found in Phase 1.4:

- [ ] Verify in code. Record: IMPLEMENTED / PARTIAL / MISSING / INCORRECT
- [ ] Flag claims that are technically true but misleading

## 2.11 Business Logic & Authorization Gaps

- [ ] Mass assignment: model creation endpoints accept only whitelisted fields (no `role`, `isAdmin`, `privilege` from user input). Search for ORM `.create(req.body)` without field filtering
- [ ] Numeric input validation: quantities, amounts, prices validated as positive before arithmetic. Search for math on user-supplied numbers without `> 0` guard
- [ ] Payment/privilege flow: privilege granted ONLY after payment confirmation. Search for status/role upgrades — verify payment check precedes them
- [ ] Soft-delete consistency: if app uses soft-delete (`deletedAt`, `paranoid`), verify ALL query paths respect it — especially raw SQL vs ORM queries
- [ ] IDOR on write operations: creation/update endpoints verify ownership, not just read endpoints. Check if `req.body.BasketId`, `req.body.UserId` etc. are validated against authenticated user
- [ ] Loose equality in auth checks: search for `!=` or `==` (instead of `!==`/`===` in JS/TS) in authorization logic — `null != undefined` is `false`, enabling bypass
- [ ] Multi-step form bypass: if security-critical flows have multiple steps (CAPTCHA → action, verify → confirm), check if later steps can be reached directly without completing earlier validation steps. Search for `step` / `stage` parameters in form handlers

## 2.12 Logging & Monitoring

- [ ] Security events logged: failed logins, auth failures, privilege changes, admin actions should produce log entries
- [ ] Logs don't contain sensitive data: no passwords, tokens, session IDs, or PII in log output. Search for `console.log`, `logger`, `logging` near sensitive variables
- [ ] Log injection: user input included in logs should be sanitized to prevent log forging (newline injection, ANSI escape sequences)
- [ ] Monitoring hooks: verify application has some mechanism to detect anomalies (rate spikes, mass failures) — even if just structured logging for external SIEM

## Stack profile: Supabase

Applies when the repo has `supabase/` (migrations, `config.toml`, Edge Functions) or uses `@supabase/supabase-js`. The browser talks to Postgres through the Data API with the public anon key, so RLS policies are the access control: read them like route handlers. Category `auth` unless noted. Evidence is the migration line of the policy or function, or the client file:line. Resolve every pre-pass policy row to a finding or a non-issue.

- [ ] RLS enabled on every table in an exposed schema (`public` and any schema in `config.toml` `[api] schemas`). A table without `enable row level security` is readable and writable by anyone holding the anon key
- [ ] No `using (true)` / `with check (true)` on tables holding personal or tenant data; `true` is fine for public catalogue data, and the non-issue names the columns
- [ ] Policies compare the row's owner or tenant column with `auth.uid()` (or a membership table keyed by it). `auth.role() = 'authenticated'`, `auth.uid() is not null` or `to authenticated` with no row condition means any signed-in user, which with open sign-up is anyone
- [ ] UPDATE policies keep ownership columns fixed: without `with check`, USING doubles as the check, so a login-only USING lets a user move rows to themselves. Column grants (`grant update (col, ...)`) or a trigger stop users writing privileged columns (`role`, `plan`, an `email` used for lookups)
- [ ] Policies that read `auth.jwt() -> 'user_metadata'` trust a field the user can edit (`auth.updateUser({ data })`); roles and tenants come from `app_metadata` or a table
- [ ] Views in exposed schemas use `security_invoker = true`, or they run as their owner and skip the base tables' RLS
- [ ] SECURITY DEFINER functions: `set search_path = ''` (or a fixed list), an explicit `auth.uid()` ownership or role check inside, and `revoke execute ... from public, anon` unless anonymous use is intended. Every function in an exposed schema is callable through `/rest/v1/rpc`
- [ ] Storage: a bucket is `public` only for files meant for everyone (category `upload`); policies on `storage.objects` tie the object path or `owner` to `auth.uid()` (`(storage.foldername(name))[1] = auth.uid()::text`), not only `bucket_id = '...'`; signed URLs are created after an ownership check
- [ ] The service-role key (`SUPABASE_SERVICE_ROLE_KEY`, `sb_secret_...`) stays in server code: never behind `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_`, never in a module imported by a `"use client"` file or a mobile app (category `exposure`). The anon or publishable key is public by design: a finding about it alone is a false positive
- [ ] Server code that uses the service-role client takes the user id from the verified session (`auth.getUser()` / `auth.getClaims()`), never from the body or query; `auth.getSession()` on the server is not an authorization check
- [ ] Edge Functions: `verify_jwt = false` in `config.toml` only for webhooks that verify a signature or for intentionally public functions; a function acting for a user reads the user from the `Authorization` JWT, not from the body
- [ ] Auth settings (category `config`): `site_url` and `additional_redirect_urls` are exact (no wildcards on shared domains), email confirmation is on for open sign-up

## Stack profile: Firebase

Applies when the repo has `firebase.json`, `firestore.rules`, `storage.rules`, `database.rules.json` or uses the `firebase` / `firebase-admin` SDKs. Clients read and write Firestore, Realtime Database and Storage directly, so the rules files are the access control. Category `auth` unless noted.

- [ ] No `allow read, write: if true` (or a test-mode `request.time < timestamp.date(...)` rule) on anything but public data; Realtime Database: no `".read": true` / `".write": true` above private data
- [ ] `if request.auth != null` alone means any signed-in user; rules compare `request.auth.uid` with the owner field or path segment (`resource.data.ownerId`, `{userId}`), and `create` checks `request.resource.data.ownerId == request.auth.uid`
- [ ] Rules are OR-ed: a broad rule on a parent path, a recursive wildcard (`{document=**}`, `{allPaths=**}`) or a subcollection rule must not grant more than the narrow ones intend
- [ ] Updates validate fields: users cannot set `role`, `plan`, `ownerId` or counters (`request.resource.data.diff(resource.data).affectedKeys().hasOnly([...])`)
- [ ] Custom-claim checks (`request.auth.token.admin == true`) rely on claims that only server code sets
- [ ] Storage rules check ownership (path segment or `firestore.get()` of the parent document), size and content type on writes
- [ ] Admin SDK credentials (service-account JSON, `FIREBASE_PRIVATE_KEY`) stay on the server, never in client bundles or committed files (category `exposure`). The web config `apiKey` is public by design
- [ ] Cloud Functions: `onCall` handlers check `request.auth` and ownership before using the Admin SDK, which bypasses rules; `onRequest` handlers verify an ID token (`verifyIdToken`) or a webhook signature. App Check (`enforceAppCheck`) is abuse protection, not authorization

## Stack profile: Laravel

Applies when the repo has `artisan`, `routes/web.php`/`routes/api.php`, Blade views or `laravel/framework` in `composer.json`. Entry points are the routes in `routes/*.php` (the pre-pass lists them with the middleware of their groups and the controller method they call); `routes/api.php` is served under `/api`. Category `auth` unless noted.

- [ ] Every route that is not public sits behind `auth` (or `auth:sanctum` for the API) in its own chain or an enclosing `Route::middleware(...)->group()`; a route added after the group closes, or `withoutMiddleware('auth')`, has none
- [ ] Staff and admin routes add `can:<ability>` (or a policy/Gate check in the controller); `auth` alone means any signed-in user, which with open registration is anyone
- [ ] Controllers load records through the user (`$request->user()->tickets()->findOrFail($id)`), a global scope, or check a policy (`$this->authorize('view', $ticket)`, `Gate::authorize`) before returning or changing them. `Model::find($id)`/`findOrFail($id)` and implicit route-model binding (`Ticket $ticket`) load any row by id
- [ ] Mass assignment (category `injection`): no `$guarded = []` on models with privileged columns (`is_admin`, `role`, `user_id`, `team_id`, `balance`, `email_verified_at`); `create()`/`update()`/`fill()` take `$request->validated()` or `$request->only([...])`, never `$request->all()`. Validation of some fields does not filter the others out of `all()`
- [ ] Raw SQL (category `injection`): `DB::raw`, `DB::select/statement/unprepared`, `whereRaw`, `orderByRaw`, `havingRaw`, `selectRaw` bind values (`?` and an array) and never interpolate request data; column and sort names from the request go through an allow-list
- [ ] Blade (category `xss`): `{!! !!}` only for HTML the app built or sanitized itself (`{!! nl2br(e($x)) !!}` is fine); user content goes through `{{ }}`. Also `Blade::compileString`, `@php echo`, `HtmlString` on user input
- [ ] CSRF (category `config`): `VerifyCsrfToken::$except` or `validateCsrfTokens(except: [...])` lists only webhooks that verify a signature; a wildcard on account, settings or payment paths turns CSRF off for state changes
- [ ] Uploads (category `upload`): validated with `mimes:`/`image` and `max:`; stored with a generated name (`store()`), not `getClientOriginalName()`; private files on a non-public disk and served through a controller that checks access. The `public` disk is reachable at `/storage/...`
- [ ] Signed URLs: routes that rely on a signature carry the `signed` middleware (or call `hasValidSignature()`); temporary links expire (`temporarySignedRoute`); a signature is not a substitute for an ownership check when the link can be forwarded
- [ ] Configuration (category `config`): `APP_DEBUG=false` and `APP_ENV=production` in production (`'debug'` must not default to true in `config/app.php`); `APP_KEY` set and not committed; Telescope, Horizon and Debugbar gated or not installed in production
- [ ] Dependencies (category `dependency`): `composer.lock` is committed and scanned (osv-scanner, or `composer audit --locked`); a missing lockfile is a coverage gap

## Stack profile: Symfony

Applies when the repo has `config/packages/*.yaml`, `config/bundles.php`, `symfony.lock` or `symfony/framework-bundle` in `composer.json`. Entry points are `#[Route]` attributes (and `@Route` annotations) on controllers and `config/routes*.yaml`; the pre-pass lists each with its `#[IsGranted]`, `denyAccessUnlessGranted` and the matching `access_control` rule. Category `auth` unless noted.

- [ ] Every non-public route is covered by `#[IsGranted]` on the method or class, `denyAccessUnlessGranted()` in the body, or an `access_control` rule in `security.yaml` (first match wins, the path is a regex: `^/admin` does not cover `/api/admin`)
- [ ] `ROLE_USER` or `IS_AUTHENTICATED` only proves login: objects loaded by id (`$repo->find($id)`, `#[MapEntity]`/ParamConverter arguments) are checked with a voter (`#[IsGranted('VIEW', 'invoice')]`, `denyAccessUnlessGranted('EDIT', $obj)`) or loaded with an owner filter
- [ ] Doctrine (category `injection`): DQL (`createQuery`), QueryBuilder (`where`/`andWhere`) and DBAL (`executeQuery`, `prepare`) bind parameters (`:name` + `setParameter`) and never concatenate request data; `orderBy` fields come from an allow-list
- [ ] Repository methods used by controllers filter by the current user, customer or tenant when the entity has an owner (`findBy(['id' => $id])` is not scoped)
- [ ] Twig (category `xss`): `|raw` only on HTML the app built or sanitized; autoescape not turned off (`{% autoescape false %}`); `Markup` objects not built from user input
- [ ] Forms keep CSRF protection on (`csrf_protection: true`); state-changing actions outside forms check `isCsrfTokenValid()` (category `config`)
- [ ] Production config (category `config`): `APP_ENV=prod`, `APP_DEBUG=0`, the web profiler and debug toolbar only `when@dev`, `APP_SECRET` not committed; `_profiler`/`_wdt` routes not reachable in production
- [ ] Dependencies: `composer.lock` scanned as for Laravel

## Stack profile: Drupal

Applies when the repo has `*.info.yml`/`*.routing.yml` (custom modules under `modules/custom/`) or `drupal/core` in `composer.json`. Entry points are the routes in `*.routing.yml`; the pre-pass lists their requirements and controller. Core and contributed modules are out of scope: audit custom code. Category `auth` unless noted.

- [ ] Every route has a real access requirement: `_permission`, `_role`, `_entity_access`, `_custom_access` or `_user_is_logged_in`. `_access: 'TRUE'` is for content meant for everyone; a route that returns user data with it is a finding
- [ ] Controllers that take an id (`{node}`, `{ticket_id}`) check that the current user may see that record (`$entity->access('view')`, an owner condition on `currentUser()->id()`); a permission like `access helpdesk portal` does not restrict which records
- [ ] Database (category `injection`): `\Drupal::database()->query()`, `db_query()` and `->where()` use placeholders (`:name` and an args array); no concatenation of request values; `->condition()` field names are constants
- [ ] Rendering (category `xss`): `Markup::create()`, `'#children'` and `{{ x|raw }}` never get user input; `'#markup'` passes through `Xss::filterAdmin` (which still allows many tags), so user text uses `'#plain_text'`, `$this->t()` with `@`/`%` placeholders, or Twig autoescaping
- [ ] CSRF (category `config`): routes that change state on GET (close, delete, approve, toggle links) carry `_csrf_token: 'TRUE'` or are forms (`_form`) with Form API tokens
- [ ] `hook_permission`/`*.permissions.yml`: sensitive permissions set `restrict access: true`; permissions are not granted to anonymous or authenticated by config or an install hook
- [ ] Settings (category `config`): `$settings['hash_salt']` and database credentials not committed; `trusted_host_patterns` set; error display off in production
- [ ] Dependencies: `composer.lock` scanned as for Laravel; contributed modules with security advisories are listed there

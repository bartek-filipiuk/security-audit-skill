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

## 2.3 Rate Limiting & Abuse Prevention

- [ ] Auth endpoints (login, register, password reset) rate-limited
- [ ] Resource-creation endpoints rate-limited (prevent spam)
- [ ] File upload size limits enforced
- [ ] If rate limiting claimed: verify it's actually active (not disabled in config, not bypassed in tests)

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

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

## 2.7 Dependency Security

- [ ] All dependencies pinned to specific versions (lockfile present and committed)
- [ ] Known advisories come from the pre-pass dependency scan (osv-scanner), never from memory. Prod tree + plausibly reachable code path → finding (cite the lockfile line and where the feature is used); dev-only → recommendation unless it runs in CI/build on untrusted input or a dev server is exposed. Scan NOT RUN → not-assessed, not "no CVEs"
- [ ] No unnecessary dependencies (more exposed code from unused packages)
- [ ] Transitive dependency risks: critical path depending on single-maintainer package?
- [ ] Dependency update mechanism exists (Dependabot, Renovate, or documented process)
- [ ] No dependencies pulled from non-standard registries without verification

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

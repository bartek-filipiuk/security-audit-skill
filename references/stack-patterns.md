# Stack-Specific Search Patterns

Use these grep/ripgrep patterns during Phase 2 to find relevant code.
Adapt based on the stack identified in Phase 1. Not exhaustive — use judgment.
The pre-pass (`prepass.md`) already enumerates entry points and unscoped Drizzle queries; use the patterns below to go further.

## Entry Points and Externally Controlled Input (JS/TS frameworks)

Express-style patterns (`req.body`, `app.get`) find nothing in these frameworks. Search for the input sources instead.

| Framework | Entry point | Externally controlled input |
|-----------|-------------|---------------------------|
| Next.js App Router | `app/**/route.ts` exports `GET`/`POST`/…; every export of a `"use server"` file (a public POST, callable without the UI); `page.tsx` server components | `request.json()`, `request.formData()`, `searchParams`, `params`, `headers()`, `cookies()`, server action arguments |
| Next.js proxy/middleware | `proxy.ts` / `middleware.ts` and its `config.matcher` | Paths outside the matcher get no check; a cookie-presence check is not authorization |
| tRPC | `name: somethingProcedure.input(...).query/mutation(...)` | `input`; `publicProcedure` has no auth, `protectedProcedure` only checks login |
| Hono | `app.get/post/...`, `app.route()`, `basePath()`, `app.use()` order | `c.req.param()`, `c.req.query()`, `c.req.json()`, `c.req.header()` |
| Better-Auth | `betterAuth({ user: { additionalFields } })`, plugins, `trustedOrigins`, `advanced.defaultCookieAttributes` | sign-up body fields: `additionalFields` default to `input: true`, so `role`/`plan` without `input: false` is mass assignment |
| AI SDK / Agent SDK / MCP | `tool({ inputSchema, execute })`, `tool("name", …)`, `server.tool(…)` | every tool argument (prompt injection, including content the model reads) |
| pg-boss / BullMQ | `boss.work(name, handler)`, `new Worker(name, …)` | `job.data`, as trusted as whoever can enqueue it |
| Stripe webhooks | `app/api/**/webhook*/route.ts` | the whole body unless `stripe.webhooks.constructEvent(rawBody, sig, secret)` runs first |

## SQL Injection

| Language | Patterns to search |
|----------|-------------------|
| Python | `execute\(.*%`, `execute\(.*f"`, `execute\(.*\.format`, `raw\(`, `extra\(.*where` |
| JS/TS | `query\(.*\$\{`, `query\(.*\+`, `\.raw\(`, `sequelize\.literal`, `knex\.raw` |
| Go | `fmt\.Sprintf.*SELECT`, `db\.Exec\(.*\+`, `db\.Query\(.*\+` |
| Ruby | `find_by_sql`, `where\(.*#\{`, `execute\(`, `sanitize_sql` (verify usage) |
| Java | `createQuery\(.*\+`, `executeQuery\(.*\+`, `Statement` (vs PreparedStatement) |
| PHP | `mysql_query\(.*\$`, `mysqli_query\(.*\$`, `->query\(.*\$`, `PDO.*\$` without prepare |

## XSS

| Framework | Patterns to search |
|-----------|-------------------|
| React | `dangerouslySetInnerHTML` |
| Vue | `v-html` |
| Angular | `bypassSecurityTrust`, `\[innerHTML\]` |
| Python/Jinja | `\|safe`, `Markup\(`, `autoescape false`, `{% raw %}` |
| EJS | `<%-` (unescaped output) |
| Handlebars | `\{\{\{` (triple-brace, unescaped) |
| Go templates | `template\.HTML\(` |
| PHP | `echo \$`, `<?=` without `htmlspecialchars` |

## Command Injection

| Language | Patterns to search |
|----------|-------------------|
| Python | `subprocess\..*shell=True`, `os\.system\(`, `os\.popen\(`, `exec\(`, `eval\(` |
| JS/TS | `child_process`, `exec\(`, `execSync\(`, `spawn\(.*shell`, `eval\(` |
| Go | `exec\.Command\(.*\+`, `os/exec` with user input |
| Ruby | `system\(`, `exec\(`, `` `...` `` (backticks), `%x\(`, `Open3` |
| PHP | `exec\(`, `shell_exec\(`, `system\(`, `passthru\(`, `proc_open\(` |

## Path Traversal

| Pattern | What to look for |
|---------|-----------------|
| All languages | `\.\./`, `\.\.\\`, path join/concat with user input |
| Python | `os\.path\.join\(.*request`, `open\(.*request`, `send_file\(` |
| JS/TS | `path\.join\(.*req`, `path\.resolve\(.*req`, `res\.sendFile\(` |
| Go | `filepath\.Join\(.*r\.`, `http\.ServeFile\(` |
| PHP | `file_get_contents\(.*\$_`, `include\(.*\$_`, `require\(.*\$_` |

## Secrets & Hardcoded Credentials

| Pattern | What to look for |
|---------|-----------------|
| All | `password\s*=\s*["']`, `secret\s*=\s*["']`, `api_key\s*=\s*["']`, `token\s*=\s*["']` |
| All | `BEGIN (RSA|DSA|EC) PRIVATE KEY`, `AKIA[0-9A-Z]{16}` (AWS key) |
| Config | `default.*password`, `fallback.*secret`, hardcoded in `if env missing` blocks |

## Cryptography Red Flags

| Pattern | Issue |
|---------|-------|
| `MD5\(`, `md5\(`, `hashlib\.md5` | Broken hash for security |
| `SHA1\(`, `sha1\(`, `hashlib\.sha1` | Broken hash for security |
| `DES`, `RC4`, `ECB` | Broken cipher/mode |
| `Math\.random`, `random\.random`, `rand\(\)` | Non-cryptographic RNG |
| `AES.*128` with `ECB` | Insecure mode |

## Deserialization

| Language | Patterns to search |
|----------|-------------------|
| Python | `pickle\.load`, `yaml\.load\(` (without SafeLoader), `marshal\.load` |
| Java | `ObjectInputStream`, `readObject\(`, `XMLDecoder` |
| PHP | `unserialize\(`, `maybe_unserialize\(` |
| Ruby | `Marshal\.load`, `YAML\.load\(` (without safe_load) |
| JS | `JSON\.parse` on unvalidated blobs is usually safe, but check `eval\(`, `Function\(` |

## Mass Assignment

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `\.create\(req\.body`, `\.build\(req\.body`, `Object\.assign\(.*req\.body`, `\{\.\.\.req\.body\}` |
| Python | `\*\*request\.data`, `serializer\.save\(`, `Model\.objects\.create\(\*\*` |
| Ruby | `\.create\(params`, `\.new\(params`, `\.update\(params` without `permit` |
| PHP | `fill\(\$request->all`, `create\(\$request->all`, `::create\(\$_POST` |

## JSONP / Cross-Domain Data Leakage

| Pattern | What to look for |
|---------|-----------------|
| All | `callback`, `jsonp`, `\?callback=`, `res\.jsonp`, `JSONP` |
| JS/TS | `res\.jsonp\(`, `\.jsonp\(`, `req\.query\.callback` |

## Null Byte Injection

| Pattern | What to look for |
|---------|-----------------|
| All | `%00`, `\x00`, `null.byte`, `nullByte`, `poisonNull` |
| JS/TS | `decodeURIComponent.*%00`, validation BEFORE null-byte strip (order-of-operations) |

## Unsafe YAML / Deserialization (JS/TS specific)

| Pattern | What to look for |
|---------|-----------------|
| JS/TS | `yaml\.load\(` (without `{ schema: SAFE_SCHEMA }`), `js-yaml` with default loader |
| All | `noent:\s*true` (XML entity expansion enabled), `yaml\.load` without safe option |

## Sensitive Field Storage

| Pattern | What to look for |
|---------|-----------------|
| All | `totpSecret`, `secret.*=.*plain`, `mfaSecret`, `otpSecret` stored without encryption |
| All | `req\.body\.UserId` or `req\.body\.userId` used in queries instead of authenticated user ID from token/session |

## Open Redirect

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `res\.redirect\(.*req`, `location\s*=.*req\.query`, `window\.location\s*=` |
| Python | `redirect\(.*request`, `HttpResponseRedirect\(.*request`, `return redirect\(` |
| PHP | `header\("Location:.*\$_`, `header\("location:.*\$_`, `wp_redirect\(.*\$_` |
| Go | `http\.Redirect\(.*r\.`, `w\.Header\(\).Set\("Location"` |
| Ruby | `redirect_to\s+params`, `redirect_to\s+request` |

## NoSQL Injection

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `\$where`, `\$gt`, `\$ne`, `\$regex`, `\$or.*req\.body`, `\.find\(.*req\.body`, `\.findOne\(.*req\.body`, `\.update\(.*req\.body` |
| Python | `\$where`, `\$gt`, `\$ne`, `collection\.find\(.*request` |
| PHP | `\$where`, `\$gt`, `\$ne`, `->find\(.*\$_` |

## SSTI (Server-Side Template Injection)

| Language | Patterns to search |
|----------|-------------------|
| Python/Jinja2 | `render_template_string\(`, `Template\(.*request`, `Environment\(.*\.from_string` |
| JS/TS | `res\.render\(.*req`, `Handlebars\.compile\(.*req`, `ejs\.render\(.*req`, `pug\.render\(.*req`, `nunjucks\.renderString\(` |
| PHP/Twig | `\->render\(.*\$_`, `Twig.*createTemplate\(`, `Blade::compileString\(` |
| Java | `Velocity.*evaluate\(`, `Freemarker.*Template\(`, `process\(.*getParameter` |
| Ruby | `ERB\.new\(.*params`, `render\s+inline:.*params` |

## Prototype Pollution

| Pattern | What to look for |
|---------|-----------------|
| JS/TS | `__proto__`, `constructor\.prototype`, `Object\.assign\(.*req`, `_\.merge\(.*req`, `_\.defaultsDeep\(.*req`, `deepmerge\(.*req`, `lodash\.merge` |
| Detection | Any recursive merge/extend function that accepts user input without filtering `__proto__` and `constructor` keys |

## Host Header Injection

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `req\.headers\.host`, `req\.headers\['x-forwarded-host'\]`, `req\.hostname` used in URL construction |
| Python | `request\.META\['HTTP_HOST'\]`, `request\.get_host\(\)` used in URL construction |
| PHP | `\$_SERVER\['HTTP_HOST'\]`, `\$_SERVER\['SERVER_NAME'\]` used in URL/link construction |

## LDAP Injection

| Language | Patterns to search |
|----------|-------------------|
| All | `ldap_search\(.*\$`, `ldap\.search\(.*req`, `search_s\(.*%s`, `(&(uid=` with string concatenation |

## PHP-Specific Patterns

| Pattern | Issue |
|---------|-------|
| `mysqli_real_escape_string` used for XSS protection | SQL escaping ≠ HTML encoding. Must also use `htmlspecialchars()` for output |
| `include\(.*\$_GET`, `include\(.*\$_POST`, `require\(.*\$_` | Local/Remote File Inclusion (LFI/RFI) |
| `extract\(\$_GET`, `extract\(\$_POST`, `extract\(\$_REQUEST` | Variable injection — overwrites local variables with user input |
| `\$\$` (variable variables) with user input | Variable variable injection |
| `preg_replace\(.*\/e` | Code execution via `/e` modifier (deprecated but still in legacy code) |
| `assert\(.*\$_` | Code execution via assert with user input |
| `create_function\(.*\$_` | Code execution via create_function with user input |
| `setcookie\(` without `httponly` or `secure` flags | Session cookie flags missing |
| `session_regenerate_id\(` missing after login | Session fixation vulnerability |

## GraphQL

| Pattern | What to look for |
|---------|-----------------|
| All | `introspection.*true`, `introspectionQuery`, `__schema`, `__type` — introspection should be disabled in production |
| All | `depthLimit`, `queryComplexity`, `costAnalysis` — if missing, DoS via deeply nested queries possible |

## WebSocket Security

| Pattern | What to look for |
|---------|-----------------|
| JS/TS | `ws\.on\('message'`, `socket\.on\('` — check if messages are validated/sanitized same as HTTP input |
| All | `cors.*origin` on WebSocket/Socket.IO config — verify origin allowlist, not wildcard |

## Insecure Randomness

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `Math\.random\(\)` used for tokens/session IDs/secrets (should use `crypto.randomBytes`) |
| PHP | `rand\(`, `mt_rand\(`, `array_rand\(` for security purposes (should use `random_bytes`, `random_int`) |
| Python | `random\.random\(`, `random\.randint\(` for security (should use `secrets` module) |
| Java | `java\.util\.Random` for security (should use `SecureRandom`) |

## BOLA (Broken Object Level Authorization)

| Language | Patterns to search |
|----------|-------------------|
| JS/TS | `req\.params\.\w+.*find(One|ById)` without `UserId` in same query, `req\.body\.id.*update\(`, `req\.params\.id.*delete\(` |
| Python/Django | `get_object_or_404\(.*pk=` without `owner=request.user`, `\.objects\.get\(id=` without `.filter(owner=` |
| Python/Flask | `request\.args\.get.*query\.get\(` without ownership check |
| Rails | `\.find\(params\[` without `.where(user_id: current_user.id)` scope |
| PHP | `->find\(\$_` or `->get\(\$_` without `where.*user_id` |
| Drizzle | `\.from\(\w+\)\.where\(eq\(\w+\.id,`, `\.update\(\w+\)`, `\.delete\(\w+\)`, `db\.query\.\w+\.find(First\|Many)` without the table's `orgId`/`userId` in the same statement (pre-pass Data Scope Scan lists them) |
| Next.js server actions | `"use server"` functions taking an id with no `getSession()`/ownership check inside the action itself |
| tRPC | `protectedProcedure`/`orgProcedure` that filter only by `input.id` |
| AI tools | `inputSchema` containing `orgId`/`userId`/`tenantId`: the model chooses the tenant |
| General | For each `/:id` endpoint: is there a `where` clause, `filter`, or explicit comparison between resource.ownerId and authenticated user? |

## BFLA (Broken Function Level Authorization)

| Pattern | What to look for |
|---------|-----------------|
| JS/TS | `app\.(get|post|put|delete)\(.*admin` → verify `isAuthorized`, `isAdmin`, or role-check middleware in same route definition |
| Python/Flask | `@app.route.*admin` → verify `@admin_required` or `@role_required` decorator |
| Django | `path.*admin` → verify `@user_passes_test`, `@permission_required`, or `IsAdminUser` permission class |
| Rails | Routes with `admin` namespace → verify `before_action :require_admin` |
| Java/Spring | `@RequestMapping.*admin` → verify `@PreAuthorize("hasRole('ADMIN')")` |
| Next.js | Auth only in the proxy `matcher`, a layout or a page while `app/api/**/route.ts` or server actions skip it (`/admin` matched, `/api/admin` not) |
| Method inconsistency | For same path: compare middleware on GET vs POST vs PUT vs DELETE. Different protection = BFLA |
| Unprotected mutations | POST/PUT/DELETE routes with no auth middleware at all — especially: checkout, payment, upgrade, transfer, delete-account |

## LLM and Agent Features

Model call sites first: `generateText\(|streamText\(|generateObject\(|streamObject\(` (AI SDK `ai`), `chat\.completions\.create|responses\.create` (`openai`), `messages\.create|messages\.stream` (`@anthropic-ai/sdk`, `anthropic`), `\.invoke\(|\.stream\(|AgentExecutor|createReactAgent|create_react_agent` (LangChain, LangGraph), `query\(` from the Claude Agent SDK, `server\.tool\(|registerTool\(` (MCP). Then follow the output and the tool arguments.

| Check | Patterns to search |
|-------|-------------------|
| Tool definitions | `tool\(\{`, `tools:\s*\[`, `type:\s*["']function["']`, `input_schema`, `@tool`, `StructuredTool`, `DynamicStructuredTool`, `server\.tool\(`; in each `execute`/handler look for `.update(`, `.delete(`, `.insert(`, `sendEmail`, `fetch(` without the session tenant id (`ctx.orgId`) in the `where` |
| Tool approval | AI SDK `needsApproval`, LangGraph `interrupt\(`, `HumanInTheLoop`, an approval state in the agent loop; its absence on tools that delete, pay, send or write |
| Tenant from the model | tool schema fields `orgId`, `userId`, `tenantId`, `accountId`, `email`, `to`, `url`, `path` (the model picks them) |
| Untrusted content in the loop | `fetch\(` or browse tools, document/PDF loaders, `RetrievalQA`, vector store `similaritySearch\(` without a tenant filter, inbound email or ticket text passed to `prompt`/`messages` together with write tools |
| Output to HTML | `dangerouslySetInnerHTML`, `innerHTML\s*=`, `v-html`, `marked\(`, `markdown-it`, `rehype-raw`, `\|safe` in the same component or route as a model call, and no `DOMPurify`, `sanitize-html`, `rehype-sanitize` |
| Output to SQL | `sql\.raw\(`, `\$queryRawUnsafe`, `\.unsafe\(`, `execute\(` with model text, `SQLDatabaseChain`, `create_sql_agent`, text-to-SQL prompts |
| Output to shell or code | `exec\(`, `execSync\(`, `spawn\(` with `shell: true`, `eval\(`, `new Function\(`, `vm\.run`, Python `exec\(`, `subprocess` with `shell=True`, `PythonREPLTool`, `ShellTool` |
| Output to URL | `fetch\(`, `axios`, `got\(`, `requests\.get\(` on a URL from model output or a tool argument; markdown image rendering of model output (`!\[`) without a host allowlist |
| Secrets in context | `process\.env\.` or `os\.environ` interpolated into `system:`/`prompt:`/`messages`, connection strings or internal hostnames in prompt templates, full DB rows passed as tool results |
| Cost and tokens | `model:` / `maxOutputTokens:` / `max_tokens:` / `maxSteps` / `stopWhen:` taken from `body`, `input` or `req.body`; LLM routes without a rate limiter (`@upstash/ratelimit`, `rateLimit`, a quota table); `stopWhen` or `max_iterations` missing in agent loops |
| Keys in the browser | `dangerouslyAllowBrowser:\s*true`, `anthropic-dangerous-direct-browser-access`, `NEXT_PUBLIC_\w*(OPENAI\|ANTHROPIC\|AI)\w*KEY`, `VITE_\w*KEY` |

## CSRF

| Framework | Patterns to search |
|-----------|-------------------|
| Next.js route handlers | `export async function (POST\|PUT\|PATCH\|DELETE)` in `app/**/route.ts` that authenticate by cookie (`getSession()`, `auth.api.getSession`, `cookies()`) with no `request.headers.get("origin")` / `sec-fetch-site` check; `request.formData()` or `request.text()` in those handlers (reachable by a cross-site form without preflight) |
| Next.js server actions | Protected by an Origin/Host comparison by default; check `serverActions.allowedOrigins` in `next.config.*` (a wildcard or broad list widens it) and proxies that rewrite `Host`/`X-Forwarded-Host` |
| Next.js GET handlers | `export async function GET` that calls `.insert(`, `.update(`, `.delete(`, sends email or connects an integration: `SameSite=Lax` cookies still arrive on top-level navigation |
| Better-Auth | `sameSite: "none"` in `advanced.defaultCookieAttributes`, `crossSubDomainCookies`, `trustedOrigins` with `*`, `disableCSRFCheck: true` |
| Hono | `csrf()` from `hono/csrf` and its `origin` option; `cors({ origin: (o) => o, credentials: true })` |
| JS/TS | Express `csrf-csrf` / `lusca` / `csurf` presence and the routes they skip; `express-session` or `cookie-session` with `sameSite: 'none'` |
| Django | `@csrf_exempt`, `CSRF_TRUSTED_ORIGINS`, `CSRF_COOKIE_SAMESITE = None`, `SESSION_COOKIE_SAMESITE = None` |
| Rails | `skip_forgery_protection`, `skip_before_action :verify_authenticity_token`, `protect_from_forgery with: :null_session` |
| PHP/Laravel | `$except` in `VerifyCsrfToken`, `validateCsrfTokens(except:`, Symfony `csrf_protection: false` |
| All | OAuth/SSO callbacks that exchange `code` without comparing `state` to a stored value; `SameSite=None` in `Set-Cookie` |

## CI/CD Workflows (GitHub Actions)

| Check | Patterns to search in `.github/workflows/*.yml` |
|-------|-------------------------------------------------|
| Privileged trigger | `pull_request_target`, `workflow_run`; then in the same workflow `ref: ${{ github.event.pull_request.head.sha }}` or `head.ref`, `refs/pull/`, `gh pr checkout`, `actions/download-artifact` followed by running what it downloaded. Install and build steps after such a checkout run the pull request's code |
| Expression injection | `\$\{\{\s*github\.event\.(issue\|pull_request\|comment\|review\|discussion\|head_commit\|commits)`, `\$\{\{\s*github\.head_ref` inside `run:` or `script:` (safe inside `env:` and `with:` values used as data) |
| Unpinned actions | `uses:\s*[^@\s]+@(?![0-9a-f]{40}\b)` (tag or branch instead of a commit SHA), `uses: docker://` without `@sha256:` |
| Secrets in logs | `echo .*secrets\.`, `toJSON\(secrets\)`, `set -x`, `printenv`, `env \| `, `secrets\..*>> "?\$GITHUB_(OUTPUT\|STEP_SUMMARY\|ENV)` |
| Token scope | `permissions:\s*write-all`, no top-level `permissions:`, `persist-credentials` not `false` in jobs that build untrusted code |
| Runners | `runs-on:\s*\[?self-hosted` in workflows triggered by `pull_request` from forks |

## Dockerfile and Compose

| Check | Patterns to search |
|-------|-------------------|
| Secrets in the image | `^(ENV\|ARG)\s+\w*(SECRET\|TOKEN\|KEY\|PASSWORD\|DATABASE_URL\|DSN)`, `COPY .*\.env`, `COPY . .` without a `.dockerignore` that excludes `.env*` and `.git` |
| User | no `^USER ` in the final stage, or `USER root` last |
| Base image | `FROM \S+:latest`, `FROM [^:@\s]+(\s\|$)` (no tag) |
| Remote fetch | `^ADD https?://`, `RUN .*(curl\|wget) .*\|\s*(sh\|bash)` without a checksum step |
| Install | `npm install` instead of `npm ci`, `pnpm install` without `--frozen-lockfile`, `COPY package.json` without the lockfile |
| Compose | `ports:` entries without `127.0.0.1:` for databases, caches and admin UIs, `privileged: true`, `/var/run/docker.sock`, `network_mode: host`, literal values for `*_PASSWORD` |

## Infrastructure as Code

| Tool | Patterns to search |
|------|-------------------|
| Terraform | `cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]` on ports 22/3306/5432/6379, `acl\s*=\s*"public-read`, `block_public_(acls\|policy)\s*=\s*false`, `encrypted\s*=\s*false`, `default\s*=\s*"` on variables named like `password`/`secret`, committed `*.tfstate` |
| Kubernetes / Helm | `privileged: true`, `runAsUser: 0`, `allowPrivilegeEscalation: true`, `hostNetwork: true`, `hostPath:`, `kind: Secret` with literal `data:`/`stringData:` committed |
| CloudFormation | `PublicAccessBlockConfiguration` absent or `false`, `CidrIp: 0.0.0.0/0` on admin ports, `NoEcho` missing on secret parameters |

## Package Manifests, Lockfiles and Registries

| Check | Patterns to search |
|-------|-------------------|
| Install scripts | `"(preinstall\|install\|postinstall\|prepare)"\s*:` whose command contains `curl`, `wget`, `\| *(sh\|bash)`, `node -e`, `https?://` |
| Lifecycle policy | `dangerouslyAllowAllBuilds`, `onlyBuiltDependencies`, `neverBuiltDependencies`, `ignore-scripts`, `enable-pre-post-scripts` in `package.json`, `.npmrc`, `pnpm-workspace.yaml` |
| Unpinned sources | `"(github\|gitlab\|bitbucket):`, `git\+(https?\|ssh)://`, `#(main\|master\|HEAD\|develop)"`, `"https?://\S+\.tgz"`, `"(latest\|\*)"` |
| Lockfile integrity | `pnpm-lock.yaml` entries with `tarball:` and no `integrity:`, `package-lock.json` `"resolved": "http://` or an unexpected host, entries without `"integrity"` |
| Lockfile enforced | `npm install`, `pnpm install` without `--frozen-lockfile`, `yarn install` without `--immutable` in CI workflows and Dockerfiles |
| Registry | `.npmrc` `registry=http://`, `strict-ssl=false`, `_authToken=` followed by a literal (not `${…}`), internal `@scope/` packages with no `@scope:registry=` line |

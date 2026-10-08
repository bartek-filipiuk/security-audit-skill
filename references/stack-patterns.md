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

## Supabase

Policies and functions live in `supabase/migrations/*.sql`; the pre-pass policy scan lists tables without RLS, `true` and login-only policies, bucket-wide storage policies, public buckets and SECURITY DEFINER functions as hotspots (kind `policy`). Read all policies of a table together: permissive policies are OR-ed.

| Area | Patterns to search |
|------|-------------------|
| RLS | `create table` without a matching `enable row level security`; `disable row level security`; `create view` without `security_invoker` |
| Policies | `using \(true\)`, `with check \(true\)`, `auth\.role\(\)`, `auth\.uid\(\) is not null`, `user_metadata`, `for update` without `with check` |
| Functions | `security definer` without `set search_path`; `grant execute .* to anon`; no `revoke execute .* from public`; `\.rpc\(` call sites |
| Storage | `storage\.buckets` with `public`, `on storage\.objects` policies without `foldername`/`auth\.uid\(\)`, `createSignedUrl\(`, `getPublicUrl\(` |
| Keys | `SERVICE_ROLE`, `service_role`, `sb_secret_`, `NEXT_PUBLIC_\w*SERVICE`, a service-key `createClient\(` in a module imported from `"use client"` |
| Server | `auth\.getSession\(\)` used for authorization; `userId`/`user_id` from `request\.json\(\)` next to a service-role client |
| Edge Functions | `supabase/functions/*/index.ts` (`Deno\.serve`), `verify_jwt = false` in `supabase/config.toml`, body fields used as the user id |

## Firebase

| Area | Patterns to search |
|------|-------------------|
| Rules | `firestore.rules`, `storage.rules`, `database.rules.json`: `if true`, `request\.time <`, `if request\.auth != null;`, `\{document=\*\*\}`, `\{allPaths=\*\*\}`, `"\.read": true`, `"\.write": true` |
| Ownership | `allow` lines without `request\.auth\.uid ==` or `== request\.auth\.uid`; updates without `affectedKeys\(\)` |
| Admin SDK | `firebase-admin`, `credential\.cert`, `private_key`, `FIREBASE_PRIVATE_KEY`, `serviceAccount` in client code or committed JSON |
| Functions | `onCall\(` without `request\.auth`/`context\.auth`; `onRequest\(` without `verifyIdToken`; `enforceAppCheck` treated as authorization |
| Client | `NEXT_PUBLIC_FIREBASE_API_KEY` is public by design; client queries that rely on the UI to filter by owner |

## Laravel

Routes live in `routes/web.php` and `routes/api.php` (`/api` prefix); the pre-pass lists each route with the middleware of its groups and resolves the controller method, so rank by what the method does. Read a model's `$fillable`/`$guarded` before judging a `create()` or `update()`.

| Area | Patterns to search |
|------|-------------------|
| Routes | `Route::(get\|post\|put\|patch\|delete\|any\|resource)\(` outside a `middleware\(.*auth` group; `withoutMiddleware\(`; admin paths without `can:` |
| Object access | `::find\(\$`, `::findOrFail\(\$`, route-model binding (`Model \$model` arguments) without `authorize\(`, `Gate::`, `->user\(\)->` |
| Mass assignment | `\$guarded = \[\]`, `->(create\|update\|fill\|forceFill)\(\$request->all\(\)`, `\$request->input\(\)` passed whole |
| Raw SQL | `DB::raw\(`, `DB::(select\|statement\|unprepared)\(`, `(where\|orderBy\|having\|select\|groupBy)Raw\(` with `"...\$` or `' .` |
| Blade | `\{!!` without `e\(`; `Blade::compileString\(`; `new HtmlString\(` on request data |
| CSRF | `\$except = \[` in `VerifyCsrfToken`, `validateCsrfTokens\(except:` |
| Uploads | `getClientOriginalName\(\)` in `storeAs\(`/`move\(`; `'public'` disk for private files; no `mimes:` rule |
| Signed URLs | `URL::signedRoute\(`, `temporarySignedRoute\(` without the `signed` middleware on the target route; `hasValidSignature` missing |
| Config | `APP_DEBUG=true` in a production env file; `'debug' => true`; `Telescope`, `Debugbar` without a gate |

## Symfony

| Area | Patterns to search |
|------|-------------------|
| Routes | `#\[Route\(` / `@Route\(` methods without `#\[IsGranted`, `denyAccessUnlessGranted\(`; `config/routes*.yaml`; `access_control` regexes in `security.yaml` |
| Object access | `->find\(\$`, `->findOneBy\(\[.id.`, `#\[MapEntity` arguments with only `ROLE_USER`; voters (`extends Voter`) that are never asked |
| Doctrine | `createQuery\(".*\$\|"\s*\.`, `->(where\|andWhere\|orWhere)\(".*\$`, `executeQuery\(` / `prepare\(` with concatenation, `orderBy\(\$` |
| Twig | `\|raw`, `{% autoescape false %}`, `new Markup\(` |
| CSRF | `csrf_protection: false`, actions without `isCsrfTokenValid\(` |
| Config | `APP_DEBUG=1`, `profiler:` / `toolbar: true` outside `when@dev`, `_profiler` routes in prod |

## Drupal

| Area | Patterns to search |
|------|-------------------|
| Routes | `*.routing.yml`: `_access: 'TRUE'`, routes without `requirements`, state-changing paths (`/delete`, `/close`, `/approve`) without `_csrf_token` |
| Controllers | controller methods taking an id without `->access\(` or a `currentUser\(\)->id\(\)` condition |
| Database | `->query\(".*\$\|"\s*\.`, `db_query\(`, `->where\(` with concatenation; `->condition\(\$` field names from input |
| Rendering | `Markup::create\(`, `'#children'`, `'#markup' => .*\$` without `\$this->t\(`/`#plain_text`, `\|raw` in Twig |
| Permissions | `*.permissions.yml` without `restrict access` on sensitive permissions; `user_role_grant_permissions\(` in install hooks |
| Tools | `composer audit --locked` or osv-scanner on `composer.lock`; Psalm `--taint-analysis` (TaintedSql, TaintedHtml) as candidates, run by the user in a sandbox |

## Django

Routes live in every `urls.py` reached through `include()` from `ROOT_URLCONF`, plus DRF routers; the pre-pass lists each with its view and guards, so rank by what the view does. Read the model's fields before judging a query: a model with a `ForeignKey` to the user model belongs to someone.

| Area | Patterns to search |
|------|-------------------|
| Routes | `path\(`, `re_path\(`, `router\.register\(` whose view has no `@login_required`, `LoginRequiredMixin`, `permission_classes`; `login_not_required`; `REST_FRAMEWORK` without `DEFAULT_PERMISSION_CLASSES` |
| DRF | `permission_classes = \[.*AllowAny`, `queryset = \w+\.objects\.all\(\)` without `def get_queryset`, `fields = "__all__"` |
| Object access | `get_object_or_404\(\w+, pk=`, `\.objects\.get\(pk=`, `\.objects\.get\(id=` without `request\.user` / `owner=` / `user=` |
| Raw SQL | `\.raw\(f"`, `\.extra\(`, `RawSQL\(`, `cursor\.execute\(f"`, `execute\(".*" %`, `\.format\(` inside SQL |
| Templates | `\|safe`, `{% autoescape off %}`, `mark_safe\(` on variables, `format_html\(` with a pre-built string |
| CSRF | `@csrf_exempt` on views that are not signed webhooks; `CsrfViewMiddleware` missing from `MIDDLEWARE` |
| Settings | `DEBUG = True`, `DEBUG = .*get\(.*"1"\)`, `ALLOWED_HOSTS = \["\*"\]`, `SECRET_KEY = "`, `SECRET_KEY = os\.environ\.get\(".*", "` |
| Files | `os\.path\.join\(.*request\.(POST\|FILES)`, `os\.path\.join\(.*\.name\)`, `open\(.*request` |
| Deserialization | `pickle\.loads\(`, `yaml\.load\(` without `SafeLoader`, `yaml\.Loader`, `jsonpickle` |

## FastAPI

| Area | Patterns to search |
|------|-------------------|
| Routes | `@(app\|router)\.(get\|post\|put\|patch\|delete)\(` whose function has no `Depends\(get_current_user` / `Security\(`; `APIRouter\(` and `include_router\(` without `dependencies=` |
| Object access | `db\.get\(\w+, \w+_id\)`, `select\(\w+\)\.where\(\w+\.id ==` without the owner column; `session\.query\(\w+\)\.get\(` |
| Response models | `response_model=` pointing at schemas with `password`, `hash`, `token`, `secret`, `totp`; routes returning ORM rows without `response_model` |
| SQL | `text\(f"`, `text\(".*" %`, `execute\(f"`, `\.format\(` in SQL |
| SSRF | `add_task\(.*url`, `httpx\.(get\|post)\(.*url`, `requests\.(get\|post)\(.*url`, `HttpUrl` fields used as request targets |
| CORS | `allow_origins=\["\*"\]` with `allow_credentials=True`; `allow_origin_regex=".\*"` |
| Cookies | `set_cookie\(` without `httponly=True`, `secure=True`, `samesite=` |

## Flask

| Area | Patterns to search |
|------|-------------------|
| Routes | `@(app\|bp\|\w+)\.route\(`, `@\w+\.(get\|post)\(` without `@login_required` / `@\w+_required` below it and no `before_request` check on the blueprint |
| Object access | `\.query\.get\(`, `get_or_404\(`, `filter_by\(id=` without `current_user` |
| SSTI | `render_template_string\(` with an f-string, `+`, `%` or `.format\(`; `Template\(.*request`, `from_string\(` |
| Files | `send_file\(.*request`, `send_file\(os\.path\.join\(`, `\.save\(os\.path\.join\(.*\.filename\)` without `secure_filename` |
| Sessions | `secret_key = "`, `config\["SECRET_KEY"\] = "`, `SECRET_KEY.*getenv\(.*, "` |
| Debug | `app\.run\(.*debug=True`, `config\["DEBUG"\] = True`, `FLASK_DEBUG=1` in production config |
| Tools | `bandit -r . -f json` (B201 debug, B301 pickle, B506 yaml.load, B608 SQL strings, B105 secrets) and `pip-audit -r requirements.txt --no-deps --disable-pip` as candidates |
